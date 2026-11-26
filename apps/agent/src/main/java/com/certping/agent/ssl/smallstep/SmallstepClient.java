// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import javax.net.ssl.SSLException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.security.auth.x500.X500Principal;

@Slf4j
@Component
class SmallstepClient {
    private static final String JSON = "application/json";

    private final AgentProperties properties;
    private final SecretStore secretStore;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final Semaphore crlFetchPermits;
    private volatile Session session;
    private volatile List<X509Certificate> issuingCertificates;

    private record Session(SmallstepCredentials credentials, HttpClient httpClient) {}

    SmallstepClient(AgentProperties properties, SecretStore secretStore,
                    ObjectMapper objectMapper, Clock clock) {
        this.properties = properties;
        this.secretStore = secretStore;
        this.objectMapper = objectMapper;
        this.clock = clock;
        int maximum = properties.getSmallstep().getMaxConcurrentCrlFetches();
        if (maximum < 1) {
            throw new IllegalArgumentException(
                    "agent.smallstep.max-concurrent-crl-fetches must be at least 1");
        }
        this.crlFetchPermits = new Semaphore(maximum);
    }

    SmallstepSignResult sign(PKCS10CertificationRequest csr, Duration validity) {
        Session current = session();
        String token = SmallstepTokenFactory.create(current.credentials(), csr, clock);
        JsonNode response = sendJson(current, "POST", "/1.0/sign",
                signBody(pem(csr), token, validity));
        List<X509Certificate> chain = parseChain(response);
        return new SmallstepSignResult(chain, current.credentials().authorityName(),
                current.credentials().provisionerName());
    }

    /** step-ca reads a non RFC 3339 {@code notAfter} as a duration from issuance. */
    static Map<String, Object> signBody(String csrPem, String ott, Duration validity) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("csr", csrPem);
        body.put("ott", ott);
        if (validity != null && validity.toHours() > 0) {
            body.put("notAfter", validity.toHours() + "h");
        }
        return body;
    }

    SmallstepRevocationService.Result revoke(
            String issuerDn, String serialNumber, String reasonValue) {
        BigInteger serial = serial(serialNumber);
        Reason reason = reason(reasonValue);
        Session current = session();
        SmallstepCrlVerifier.Status existing = revocationStatus(current, issuerDn, serial);
        if (existing.revoked()) {
            return new SmallstepRevocationService.Result(
                    true, existing.reason(), existing.observedAt());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("serial", serial.toString());
        body.put("ott", SmallstepTokenFactory.createRevocation(
                current.credentials(), serial.toString(), clock));
        body.put("reasonCode", reason.code());
        body.put("reason", reason.name());
        // step-ca v0.30.x requires passive=true. With CRLs enabled, the same durable
        // revocation record is included in the signed CRL used for confirmation.
        body.put("passive", true);
        try {
            sendJson(current, "POST", "/1.0/revoke", body);
        } catch (AgentException revokeFailure) {
            SmallstepCrlVerifier.Status reconciled;
            try {
                reconciled = revocationStatus(current, issuerDn, serial);
            } catch (AgentException statusFailure) {
                statusFailure.addSuppressed(revokeFailure);
                throw statusFailure;
            }
            if (reconciled.revoked()) {
                return new SmallstepRevocationService.Result(
                        true, reconciled.reason(), reconciled.observedAt());
            }
            throw revokeFailure;
        }
        SmallstepCrlVerifier.Status confirmed = revocationStatus(current, issuerDn, serial);
        if (!confirmed.revoked()) {
            throw new TransientAgentException("SMALLSTEP_REVOCATION_NOT_CONFIRMED",
                    "Smallstep accepted the revocation but its signed CRL does not contain the certificate");
        }
        return new SmallstepRevocationService.Result(
                false, confirmed.reason(), confirmed.observedAt());
    }

    boolean isRevoked(String issuerDn, String serialNumber) {
        return revocationStatus(session(), issuerDn, serial(serialNumber)).revoked();
    }

    String probeVersion() {
        JsonNode response = sendJson(session(), "GET", "/version", null);
        return response.path("version").asString("unknown");
    }

    String connectedEndpoint() { return session().credentials().baseUrl(); }
    String provisionerName() { return session().credentials().provisionerName(); }
    String authorityName() { return session().credentials().authorityName(); }

    private SmallstepCrlVerifier.Status revocationStatus(
            Session current, String expectedIssuerDn, BigInteger serial) {
        acquireCrlPermit();
        try {
            X509CRL crl = fetchCrl(current);
            X509Certificate issuer = crlIssuer(current, crl.getIssuerX500Principal());
            return SmallstepCrlVerifier.status(
                    crl, expectedIssuerDn, serial, issuer, clock.instant());
        } finally {
            crlFetchPermits.release();
        }
    }

    void verifyRevocationReady() {
        acquireCrlPermit();
        try {
            Session current = session();
            X509CRL crl = fetchCrl(current);
            X509Certificate issuer = crlIssuer(current, crl.getIssuerX500Principal());
            SmallstepCrlVerifier.status(crl, crl.getIssuerX500Principal().getName(),
                    BigInteger.ZERO, issuer, clock.instant());
        } finally {
            crlFetchPermits.release();
        }
    }

    private void acquireCrlPermit() {
        if (!crlFetchPermits.tryAcquire()) {
            throw new TransientAgentException("SMALLSTEP_CRL_BUSY",
                    "This agent is already processing its maximum concurrent Smallstep CRLs");
        }
    }

    private X509CRL fetchCrl(Session current) {
        HttpResponse<InputStream> response = sendStream(current, "/1.0/crl");
        try (InputStream body = response.body()) {
            int maximum = properties.getSmallstep().getMaxCrlBytes();
            if (maximum < 1024) {
                throw new PermanentAgentException("SMALLSTEP_CONFIG_INVALID",
                        "agent.smallstep.max-crl-bytes must be at least 1024");
            }
            long contentLength = response.headers().firstValueAsLong("Content-Length").orElse(-1);
            if (contentLength > maximum) {
                throw new PermanentAgentException("SMALLSTEP_CRL_TOO_LARGE",
                        "Smallstep CRL exceeds the configured response-size limit");
            }
            byte[] encoded = readCrlBody(body, maximum + 1);
            if (encoded.length > maximum) {
                throw new PermanentAgentException("SMALLSTEP_CRL_TOO_LARGE",
                        "Smallstep CRL exceeds the configured response-size limit");
            }
            return SmallstepCrlVerifier.parse(encoded);
        } catch (PermanentAgentException | TransientAgentException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new TransientAgentException("SMALLSTEP_CRL_INVALID",
                    "Smallstep returned an unreadable CRL", exception);
        }
    }

    byte[] readCrlBody(InputStream body, int maximumBytes) {
        FutureTask<byte[]> read = new FutureTask<>(() -> body.readNBytes(maximumBytes));
        Thread reader = Thread.ofVirtual().name("smallstep-crl-reader").start(read);
        try {
            return read.get(timeout().toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            closeQuietly(body);
            read.cancel(true);
            throw new TransientAgentException("SMALLSTEP_CRL_TIMEOUT",
                    "Smallstep CRL response body exceeded the request timeout", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            closeQuietly(body);
            read.cancel(true);
            throw new TransientAgentException(
                    "SMALLSTEP_INTERRUPTED", "Smallstep CRL read was interrupted", exception);
        } catch (ExecutionException exception) {
            throw new TransientAgentException("SMALLSTEP_CRL_INVALID",
                    "Smallstep CRL response body could not be read", exception.getCause());
        } finally {
            if (!read.isDone()) {
                closeQuietly(body);
                read.cancel(true);
                reader.interrupt();
            }
        }
    }

    private static void closeQuietly(InputStream body) {
        try {
            body.close();
        } catch (Exception ignored) {
            // Preserve the timeout or interruption that caused this cleanup.
        }
    }

    private X509Certificate crlIssuer(Session current, X500Principal issuerName) {
        X509Certificate issuer = findIssuer(issuerCertificates(current, false), issuerName);
        if (issuer != null) return issuer;
        issuer = findIssuer(issuerCertificates(current, true), issuerName);
        if (issuer != null) return issuer;
        throw new PermanentAgentException("SMALLSTEP_CRL_ISSUER_UNKNOWN",
                "Smallstep CRL was not signed by the configured authority intermediate");
    }

    private static X509Certificate findIssuer(
            List<X509Certificate> certificates, X500Principal issuerName) {
        return certificates.stream()
                .filter(certificate -> certificate.getSubjectX500Principal().equals(issuerName))
                .findFirst().orElse(null);
    }

    private List<X509Certificate> issuerCertificates(Session current, boolean refresh) {
        List<X509Certificate> cached = issuingCertificates;
        if (!refresh && cached != null) return cached;
        synchronized (this) {
            if (!refresh && issuingCertificates != null) return issuingCertificates;
            JsonNode response = sendJson(current, "GET", "/1.0/intermediates", null);
            issuingCertificates = SmallstepCrlVerifier.trustedIntermediates(
                    current.credentials().rootCaPem(), response.path("crts"));
            return issuingCertificates;
        }
    }

    private HttpResponse<InputStream> sendStream(Session current, String path) {
        try {
            HttpRequest request = HttpRequest.newBuilder(
                            URI.create(current.credentials().baseUrl() + path))
                    .timeout(timeout()).header(HttpHeaders.ACCEPT, "application/pkix-crl")
                    .GET().build();
            HttpResponse<InputStream> response = current.httpClient().send(
                    request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() == 404) {
                response.body().close();
                throw new PermanentAgentException("SMALLSTEP_CRL_NOT_CONFIGURED",
                        "Smallstep CRLs are not enabled; enable CRLs and generateOnRevoke");
            }
            if (response.statusCode() >= 500) {
                response.body().close();
                throw new TransientAgentException("SMALLSTEP_CRL_UNAVAILABLE",
                        "Smallstep CRL is unavailable (HTTP " + response.statusCode() + ")");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                response.body().close();
                throw new PermanentAgentException("SMALLSTEP_CRL_REJECTED",
                        "Smallstep rejected the CRL request with HTTP " + response.statusCode());
            }
            return response;
        } catch (PermanentAgentException | TransientAgentException exception) {
            throw exception;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException(
                    "SMALLSTEP_INTERRUPTED", "Smallstep CRL request was interrupted", exception);
        } catch (Exception exception) {
            if (hasCause(exception, SSLException.class)) {
                throw new PermanentAgentException("SMALLSTEP_TLS_HANDSHAKE_FAILED",
                        "Smallstep TLS verification failed; rootCaPem does not match the authority", exception);
            }
            throw new TransientAgentException("SMALLSTEP_NETWORK_ERROR",
                    "Smallstep CRL request failed: " + exception.getMessage(), exception);
        }
    }

    private JsonNode sendJson(Session current, String method, String path, Map<String, Object> body) {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(current.credentials().baseUrl() + path))
                    .timeout(timeout()).header(HttpHeaders.ACCEPT, JSON);
            if (body == null) {
                request.GET();
            } else {
                request.header(HttpHeaders.CONTENT_TYPE, JSON)
                        .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)));
            }
            HttpResponse<String> response = current.httpClient().send(
                    request.build(), HttpResponse.BodyHandlers.ofString());
            if (isUnconfirmedDuplicateRevocation(path, response)) {
                throw new TransientAgentException("SMALLSTEP_REVOCATION_NOT_CONFIRMED",
                        "Smallstep reports the certificate as already revoked; waiting for signed CRL confirmation");
            }
            if (response.statusCode() == 401 || response.statusCode() == 403) {
                throw new PermanentAgentException("SMALLSTEP_AUTH_FAILED",
                        "Smallstep rejected the JWK provisioner token");
            }
            if (response.statusCode() >= 500) {
                throw new TransientAgentException("SMALLSTEP_SERVER_ERROR",
                        "Smallstep returned HTTP " + response.statusCode());
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new PermanentAgentException("SMALLSTEP_REQUEST_REJECTED",
                        safeError(response.body(), response.statusCode()));
            }
            return objectMapper.readTree(response.body());
        } catch (PermanentAgentException | TransientAgentException exception) {
            throw exception;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new TransientAgentException("SMALLSTEP_INTERRUPTED", "Smallstep request was interrupted", exception);
        } catch (Exception exception) {
            if (hasCause(exception, SSLException.class)) {
                throw new PermanentAgentException("SMALLSTEP_TLS_HANDSHAKE_FAILED",
                        "Smallstep TLS verification failed; rootCaPem does not match the authority", exception);
            }
            throw new TransientAgentException("SMALLSTEP_NETWORK_ERROR",
                    "Smallstep request failed: " + exception.getMessage(), exception);
        }
    }

    private String safeError(String body, int status) {
        try {
            String message = objectMapper.readTree(body).path("message").asString("");
            return message.isBlank() ? "Smallstep rejected the request with HTTP " + status
                    : "Smallstep rejected the request: " + truncate(message, 500);
        } catch (Exception ignored) {
            return "Smallstep rejected the request with HTTP " + status;
        }
    }

    private static boolean isUnconfirmedDuplicateRevocation(
            String path, HttpResponse<String> response) {
        return "/1.0/revoke".equals(path)
                && (response.statusCode() == 400 || response.statusCode() == 403)
                && response.body() != null
                && response.body().toLowerCase(Locale.ROOT).contains("already revoked");
    }

    private List<X509Certificate> parseChain(JsonNode response) {
        try {
            List<X509Certificate> certificates = new ArrayList<>();
            JsonNode chain = response.path("certChain");
            if (chain.isArray()) {
                for (JsonNode certificate : chain) certificates.add(parseCertificate(certificate.asString()));
            }
            if (certificates.isEmpty() && response.hasNonNull("crt")) {
                certificates.add(parseCertificate(response.path("crt").asString()));
                if (response.hasNonNull("ca")) certificates.add(parseCertificate(response.path("ca").asString()));
            }
            if (certificates.isEmpty()) throw new IllegalArgumentException("response contained no certificate");
            return List.copyOf(certificates);
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_RESPONSE_INVALID",
                    "Could not parse the Smallstep certificate response", exception);
        }
    }

    private Session session() {
        Session current = session;
        if (current != null) return current;
        synchronized (this) {
            if (session != null) return session;
            AgentProperties.SmallstepProperties config = properties.getSmallstep();
            SmallstepCredentials credentials = SmallstepCredentials.parse(
                    resolveCredentialsJson(config), objectMapper, config.getBaseUrl());
            session = new Session(credentials, SmallstepTlsContextFactory.create(credentials.rootCaPem(), timeout()));
            log.info("Smallstep session established: baseUrl={}, authorityName={}, provisionerName={}",
                    credentials.baseUrl(), credentials.authorityName(), credentials.provisionerName());
            return session;
        }
    }

    private String resolveCredentialsJson(AgentProperties.SmallstepProperties config) {
        if (config.getCredentialsJson() != null && !config.getCredentialsJson().isBlank()) {
            log.debug("Smallstep credential resolved from agent.smallstep.credentials-json (literal)");
            return config.getCredentialsJson();
        }
        if (config.getCredentialPath() != null && !config.getCredentialPath().isBlank()) {
            log.debug("Smallstep credential resolved from agent.smallstep.credential-path via SecretStore");
            return secretStore.read(config.getCredentialPath());
        }
        throw new PermanentAgentException("SMALLSTEP_CONFIG_MISSING",
                "agent.smallstep.credential-path or agent.smallstep.credentials-json is required");
    }

    private Duration timeout() {
        return Duration.ofSeconds(Math.max(1, properties.getSmallstep().getRequestTimeoutSeconds()));
    }
    private static X509Certificate parseCertificate(String pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
    }
    private static BigInteger serial(String value) {
        String normalized = value == null ? "" : value.trim().replace(":", "");
        if (normalized.regionMatches(true, 0, "0x", 0, 2)) normalized = normalized.substring(2);
        if (normalized.isEmpty() || !normalized.matches("[0-9a-fA-F]+")) {
            throw new PermanentAgentException("SMALLSTEP_SERIAL_INVALID",
                    "Smallstep certificate serial number must be hexadecimal");
        }
        return new BigInteger(normalized, 16);
    }
    private static Reason reason(String value) {
        try {
            Reason reason = Reason.valueOf(value == null ? "" : value.trim().toUpperCase(Locale.ROOT));
            if (!SAFE_REASONS.contains(reason)) throw new IllegalArgumentException();
            return reason;
        } catch (IllegalArgumentException exception) {
            throw new PermanentAgentException("SMALLSTEP_REVOCATION_REASON_UNSUPPORTED",
                    "Unsupported Smallstep leaf-certificate revocation reason: " + value);
        }
    }
    private static String pem(PKCS10CertificationRequest csr) {
        try {
            StringWriter output = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(output)) { writer.writeObject(csr); }
            return output.toString();
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_CSR_INVALID", "Could not encode CSR", exception);
        }
    }
    private static boolean hasCause(Throwable error, Class<? extends Throwable> type) {
        for (Throwable current = error; current != null; current = current.getCause()) {
            if (type.isInstance(current)) return true;
            if (current.getCause() == current) break;
        }
        return false;
    }
    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max);
    }
    private static final EnumSet<Reason> SAFE_REASONS = EnumSet.allOf(Reason.class);
    private enum Reason {
        UNSPECIFIED(0), KEY_COMPROMISE(1), AFFILIATION_CHANGED(3), SUPERSEDED(4),
        CESSATION_OF_OPERATION(5), PRIVILEGES_WITHDRAWN(9);
        private final int code;
        Reason(int code) { this.code = code; }
        int code() { return code; }
    }
}
