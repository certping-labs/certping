// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Slf4j
class F5BigIpRestClient {

    private static final java.time.Duration REQUEST_TIMEOUT = java.time.Duration.ofSeconds(60);

    private final ObjectMapper objectMapper;
    private final F5BigIpAuthClient auth;
    private final String baseUrl;

    F5BigIpRestClient(ObjectMapper objectMapper, F5BigIpAuthClient auth) {
        this.objectMapper = objectMapper;
        this.auth = auth;
        this.baseUrl = auth.baseUrl();
    }

    void uploadFileChunked(String filename, byte[] bytes, int chunkSizeBytes) throws Exception {
        if (bytes == null || bytes.length == 0) {
            throw new PermanentAgentException("DEPLOY_F5_UPLOAD_EMPTY",
                    "Refusing to upload empty file: " + filename);
        }

        int total = bytes.length;
        int offset = 0;
        while (offset < total) {
            int endExclusive = Math.min(offset + chunkSizeBytes, total);
            int endInclusive = endExclusive - 1;
            byte[] chunk = java.util.Arrays.copyOfRange(bytes, offset, endExclusive);

            final int rangeStart = offset;
            final int rangeEndInclusive = endInclusive;

                HttpResponse<String> resp = auth.sendWithAuth(token -> HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/mgmt/shared/file-transfer/uploads/" + filename))
                    .timeout(REQUEST_TIMEOUT)
                    .header("X-F5-Auth-Token", token)
                    .header("Content-Type", "application/octet-stream")
                .header("Content-Range", rangeStart + "-" + rangeEndInclusive + "/" + total)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(chunk))
                    .build());
            int status = resp.statusCode();
            if (status != 200 && status != 201) {
                throw wrapF5Error("DEPLOY_F5_UPLOAD_FAILED", resp);
            }

            offset = endExclusive;
        }

        log.info("F5 upload complete: filename={}, bytes={}", filename, total);
    }

    void installCertObject(String name, String filename) throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("command", "install");
        body.put("name", name);
        body.put("from-local-file", "/var/config/rest/downloads/" + filename);

        HttpResponse<String> resp = sendJson("POST", "/mgmt/tm/sys/crypto/cert", body);
        accept2xx(resp, "DEPLOY_F5_INSTALL_CERT_FAILED");
    }

    void installKeyObject(String name, String filename) throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("command", "install");
        body.put("name", name);
        body.put("from-local-file", "/var/config/rest/downloads/" + filename);

        HttpResponse<String> resp = sendJson("POST", "/mgmt/tm/sys/crypto/key", body);
        accept2xx(resp, "DEPLOY_F5_INSTALL_KEY_FAILED");
    }

    void patchClientSslProfile(String partition, String profileName, String certName, String keyName) throws Exception {
        String part = partition == null || partition.isBlank() ? "Common" : partition.trim();
        String prof = profileName.trim();

        String profilePath = "/mgmt/tm/ltm/profile/client-ssl/~" + part + "~" + prof;

        // Read existing profile to preserve certKeyChain name (default/first entry).
        HttpResponse<String> current = sendJson("GET", profilePath, null);
        if (current.statusCode() == 404) {
            throw new PermanentAgentException("DEPLOY_F5_PROFILE_NOT_FOUND",
                    "F5 client SSL profile not found: partition=" + part + " profile=" + prof);
        }
        accept2xx(current, "DEPLOY_F5_PROFILE_GET_FAILED");

        String chainName = "default";
        try {
            JsonNode root = objectMapper.readTree(current.body());
            JsonNode chain = root.path("certKeyChain");
            if (chain.isArray() && !chain.isEmpty()) {
                JsonNode first = chain.get(0);
                String name = first.path("name").asString("");
                if (!name.isBlank()) chainName = name;
            }
        } catch (Exception e) {
            log.warn("Failed to parse certKeyChain name from profile; using 'default': {}", e.getMessage());
        }

        String certRef = "/" + part + "/" + certName;
        String keyRef = "/" + part + "/" + keyName;

        ObjectNode payload = objectMapper.createObjectNode();
        var array = payload.putArray("certKeyChain");
        ObjectNode entry = objectMapper.createObjectNode();
        entry.put("name", chainName);
        entry.put("cert", certRef);
        entry.put("key", keyRef);
        array.add(entry);

        HttpResponse<String> resp = sendJson("PATCH", profilePath, payload);
        accept2xx(resp, "DEPLOY_F5_PROFILE_PATCH_FAILED");

        log.info("F5 client SSL profile patched: partition={}, profile={}, chainName={}, certRef={}",
                part, prof, chainName, certRef);
    }

    /**
     * Find every client-SSL profile in {@code partition} whose first {@code certKeyChain} entry
     * references {@code /{partition}/{certName}}. Used to discover all profiles bound to the
     * prior rotation's cert, so SNI-style multi-profile-per-VS setups patch every profile.
     */
    List<String> findProfilesUsingCert(String partition, String certName) throws Exception {
        String part = partition == null || partition.isBlank() ? "Common" : partition.trim();
        String certRef = "/" + part + "/" + certName;

        // List all client-SSL profiles in this partition.
        String listPath = "/mgmt/tm/ltm/profile/client-ssl?$filter=partition+eq+" + part;
        HttpResponse<String> resp = sendJson("GET", listPath, null);
        accept2xx(resp, "DEPLOY_F5_PROFILE_LIST_FAILED");

        List<String> matching = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(resp.body());
            JsonNode items = root.path("items");
            if (!items.isArray()) return matching;
            for (JsonNode item : items) {
                JsonNode chain = item.path("certKeyChain");
                if (!chain.isArray() || chain.isEmpty()) continue;
                String boundCert = chain.get(0).path("cert").asString("");
                if (certRef.equals(boundCert)) {
                    String name = item.path("name").asString("");
                    if (!name.isBlank()) matching.add(name);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse client-SSL profile list response: {}", e.getMessage());
        }
        return matching;
    }

    /**
     * Discover client-SSL profiles in {@code partition} whose currently-bound certificate
     * covers any of {@code targetHostnames} (with wildcard semantics in either direction —
     * see {@link CertificateIdentityUtils#hostnameMatches}). Used as a third-tier first-deploy
     * bootstrap when neither {@code result.profilesPatched} nor {@code scope.clientSslProfiles}
     * is available: the new cert's CN+SANs drive the profile selection.
     *
     * <p>Returns profile names (no {@code /partition/} prefix). Profiles whose bound cert can't
     * be fetched (404, parse error) are skipped quietly — they likely point at a deleted or
     * factory cert and aren't operationally relevant.
     */
    List<String> findProfilesByCertHostnames(String partition, List<String> targetHostnames) throws Exception {
        if (targetHostnames == null || targetHostnames.isEmpty()) return List.of();
        String part = partition == null || partition.isBlank() ? "Common" : partition.trim();

        String listPath = "/mgmt/tm/ltm/profile/client-ssl?$filter=partition+eq+" + part;
        HttpResponse<String> resp = sendJson("GET", listPath, null);
        accept2xx(resp, "DEPLOY_F5_PROFILE_LIST_FAILED");

        List<String> matching = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(resp.body());
            JsonNode items = root.path("items");
            if (!items.isArray()) return matching;

            for (JsonNode item : items) {
                String profileName = item.path("name").asString("");
                if (profileName.isBlank()) continue;

                JsonNode chain = item.path("certKeyChain");
                if (!chain.isArray() || chain.isEmpty()) continue;
                String boundCertRef = chain.get(0).path("cert").asString("");
                if (boundCertRef.isBlank()) continue;

                Set<String> certHostnames = fetchCertHostnames(boundCertRef);
                if (certHostnames.isEmpty()) continue;

                if (anyHostnameOverlaps(certHostnames, targetHostnames)) {
                    matching.add(profileName);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse client-SSL profile list during SAN discovery: {}", e.getMessage());
        }
        return matching;
    }

    /**
     * Fetch the F5 SSL cert object's hostnames — Subject CN + each {@code DNS:} SAN.
     * Returns an empty set if the cert can't be fetched or parsed (caller treats as no match).
     */
    private Set<String> fetchCertHostnames(String certRef) {
        // certRef format: "/Common/api-prod_v1" → "/mgmt/tm/sys/file/ssl-cert/~Common~api-prod_v1"
        String trimmed = certRef.trim();
        if (!trimmed.startsWith("/")) return Set.of();
        String tilde = "~" + trimmed.substring(1).replace('/', '~');
        String path = "/mgmt/tm/sys/file/ssl-cert/" + tilde;

        try {
            HttpResponse<String> resp = sendJson("GET", path, null);
            if (resp.statusCode() == 404) return Set.of();
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) return Set.of();

            JsonNode root = objectMapper.readTree(resp.body());
            Set<String> out = new LinkedHashSet<>();

            String cn = extractCnFromSubjectDn(root.path("subject").asString(""));
            if (!cn.isBlank()) out.add(cn);

            String sanField = root.path("subjectAlternativeName").asString("");
            for (String san : parseDnsSans(sanField)) {
                if (!san.isBlank()) out.add(san);
            }
            return out;
        } catch (Exception e) {
            log.debug("F5 cert fetch failed for {} during SAN discovery: {}", certRef, e.getMessage());
            return Set.of();
        }
    }

    /** Pull {@code CN=} from an LDAP-style DN string. F5's {@code subject} field is {@code "CN=foo,O=bar,..."}. */
    private static String extractCnFromSubjectDn(String dn) {
        if (dn == null || dn.isBlank()) return "";
        for (String part : dn.split(",")) {
            String p = part.trim();
            if (p.regionMatches(true, 0, "CN=", 0, 3)) {
                return p.substring(3).trim();
            }
        }
        return "";
    }

    /** Parse F5's {@code subjectAlternativeName} string {@code "DNS:foo.com, DNS:*.bar.com"} into hostnames. */
    private static List<String> parseDnsSans(String sanField) {
        if (sanField == null || sanField.isBlank()) return List.of();
        List<String> out = new ArrayList<>();
        for (String part : sanField.split(",")) {
            String p = part.trim();
            if (p.regionMatches(true, 0, "DNS:", 0, 4)) {
                out.add(p.substring(4).trim());
            }
        }
        return out;
    }

    private static boolean anyHostnameOverlaps(Set<String> certHostnames, List<String> targets) {
        for (String c : certHostnames) {
            for (String t : targets) {
                if (CertificateIdentityUtils.hostnameMatches(c, t)) return true;
            }
        }
        return false;
    }

    /**
     * Returns the names of HA Sync-Failover device groups configured on this BIG-IP, or empty
     * if standalone. Used by the adapter to auto-detect whether to sync.
     */
    List<String> detectDeviceGroups() throws Exception {
        HttpResponse<String> resp = sendJson("GET", "/mgmt/tm/cm/device-group", null);
        accept2xx(resp, "DEPLOY_F5_DEVICE_GROUP_LIST_FAILED");

        List<String> groups = new ArrayList<>();
        try {
            JsonNode root = objectMapper.readTree(resp.body());
            JsonNode items = root.path("items");
            if (!items.isArray()) return groups;
            for (JsonNode item : items) {
                String type = item.path("type").asString("");
                String name = item.path("name").asString("");
                // Skip auto-managed device_trust_group (always present, not user-meaningful).
                if (name.isBlank() || "device_trust_group".equalsIgnoreCase(name)) continue;
                if ("sync-failover".equalsIgnoreCase(type) || "sync-only".equalsIgnoreCase(type)) {
                    groups.add(name);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse device-group list response: {}", e.getMessage());
        }
        return groups;
    }

    void saveConfig() throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("command", "save");
        HttpResponse<String> resp = sendJson("POST", "/mgmt/tm/sys/config", body);
        accept2xx(resp, "DEPLOY_F5_SAVE_FAILED");
    }

    void syncToDeviceGroup(String deviceGroup) throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("command", "run");
        body.put("utilCmdArgs", "config-sync to-group " + deviceGroup);
        HttpResponse<String> resp = sendJson("POST", "/mgmt/tm/cm/config-sync", body);
        accept2xx(resp, "DEPLOY_F5_SYNC_FAILED");
    }

    void pollSyncStatus() throws Exception {
        // Poll up to ~5 minutes.
        for (int i = 0; i < 60; i++) {
            Thread.sleep(5_000L);
            HttpResponse<String> resp = sendJson("GET", "/mgmt/tm/cm/sync-status", null);
            accept2xx(resp, "DEPLOY_F5_SYNC_STATUS_FAILED");

            String body = resp.body() == null ? "" : resp.body();
            String lower = body.toLowerCase(Locale.ROOT);
            if (lower.contains("in sync") || lower.contains("standalone")) {
                log.info("F5 sync-status indicates in-sync/standalone");
                return;
            }
        }

        // Do not hard-fail; HA sync can be slow or asynchronous.
        log.warn("Timed out waiting for F5 sync-status to report 'in sync'");
    }

    void verifyDomainsBestEffort(List<String> domains, String certPem) {
        X509Certificate expected = parseLeafCert(certPem);
        if (expected == null) {
            log.warn("Skipping F5 domain verification: unable to parse expected leaf certificate");
            return;
        }

        for (String domain : domains) {
            if (domain == null || domain.isBlank()) continue;
            try {
                X509Certificate actual = fetchServerLeafCert(domain.trim(), 443);
                if (actual == null) {
                    log.warn("F5 domain verification skipped: unable to fetch leaf cert for domain={}", domain);
                    continue;
                }

                if (!expected.getSerialNumber().equals(actual.getSerialNumber())) {
                    // Often propagation-related; treat as transient so the message can retry.
                    throw new TransientAgentException("DEPLOY_F5_VERIFY_MISMATCH",
                            "Deployed cert not yet observed on domain=" + domain);
                }
                log.info("F5 domain verification OK: domain={} serial={}", domain, actual.getSerialNumber());

            } catch (TransientAgentException e) {
                throw e;
            } catch (Exception e) {
                // Best-effort: don't block rotations on DNS/egress/TLS trust issues.
                log.warn("F5 domain verification skipped: domain={} error={}", domain, e.getMessage());
            }
        }
    }

    private X509Certificate parseLeafCert(String pem) {
        try {
            String first = extractFirstCertPem(pem);
            if (first == null) return null;
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(first.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    private String extractFirstCertPem(String pem) {
        if (pem == null) return null;
        int begin = pem.indexOf("-----BEGIN CERTIFICATE-----");
        if (begin < 0) return null;
        int end = pem.indexOf("-----END CERTIFICATE-----", begin);
        if (end < 0) return null;
        end += "-----END CERTIFICATE-----".length();
        return pem.substring(begin, end);
    }

    private X509Certificate fetchServerLeafCert(String host, int port) throws Exception {
        javax.net.ssl.SSLSocketFactory factory = (javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault();
        try (javax.net.ssl.SSLSocket socket = (javax.net.ssl.SSLSocket) factory.createSocket(host, port)) {
            socket.setSoTimeout(10_000);
            socket.startHandshake();
            java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain == null || chain.length == 0) return null;
            return (X509Certificate) chain[0];
        }
    }

    private HttpResponse<String> sendJson(String method, String path, JsonNode body) throws Exception {
        return auth.sendWithAuth(token -> {
            HttpRequest.Builder b = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .timeout(REQUEST_TIMEOUT)
                    .header("X-F5-Auth-Token", token);

            if (body != null) {
                b.header("Content-Type", "application/json");
            }

            return switch (method) {
                case "GET" -> b.GET().build();
                case "POST" -> b.POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
                case "PATCH" -> b.method("PATCH", HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8)).build();
                default -> throw new IllegalArgumentException("Unsupported method: " + method);
            };
        });
    }

    private void accept2xx(HttpResponse<String> resp, String code) {
        int status = resp.statusCode();
        if (status < 200 || status >= 300) {
            throw wrapF5Error(code, resp);
        }
    }

    private RuntimeException wrapF5Error(String code, HttpResponse<String> resp) {
        int status = resp.statusCode();
        String body = safeBody(resp.body());
        String msg = "F5 iControl REST error (HTTP " + status + "): " + body;
        if (status == 429 || status == 503) {
            // F5 throttled / unavailable; honour Retry-After.
            Duration retryAfter = resp.headers().firstValue("Retry-After")
                    .flatMap(RateLimitClassifier::parseRetryAfterValueOpt)
                    .orElse(null);
            return new RetryableAgentException("DEPLOY_PROVIDER_THROTTLED",
                    "f5 big-ip REST call was rate-limited (HTTP " + status + "): " + body,
                    retryAfter);
        }
        if (status >= 500) {
            return new TransientAgentException(code, msg);
        }
        if (status == 401 || status == 403) {
            return new PermanentAgentException(code, "F5 access denied (HTTP " + status + "): " + body);
        }
        return new PermanentAgentException(code, msg);
    }

    private String safeBody(String body) {
        if (body == null) return "";
        String trimmed = body.trim();
        if (trimmed.length() > 3000) {
            return trimmed.substring(0, 3000) + "...";
        }
        return trimmed;
    }

    /** Deduplicate a list, preserving order. */
    static List<String> dedupe(List<String> input) {
        if (input == null) return List.of();
        Set<String> seen = new LinkedHashSet<>();
        for (String s : input) {
            if (s != null && !s.isBlank()) seen.add(s.trim());
        }
        return new ArrayList<>(seen);
    }
}
