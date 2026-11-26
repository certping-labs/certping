// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.f5;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Exercises {@link F5BigIpCertRotator} end-to-end against an in-process HttpServer
 * standing in for the F5 BIG-IP iControl REST API. The rotator constructs its own
 * {@link F5BigIpAuthClient} / {@link F5BigIpRestClient}, so the only seam available
 * is the HTTP layer.
 */
class F5BigIpCertRotatorTest {

    private HttpsServer server;
    private int port;
    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();
    private final FakeF5Router router = new FakeF5Router();

    @BeforeEach
    void setUp() throws Exception {
        SSLContext ctx = buildSelfSignedSslContext();
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(ctx));
        server.createContext("/", router);
        server.setExecutor(null);
        server.start();
        port = server.getAddress().getPort();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private F5BigIpConfig cfg(List<String> profiles, boolean installOnly, List<String> hostnames) {
        // verifySsl=false so the trust-all manager accepts our self-signed cert.
        return new F5BigIpConfig(
                "127.0.0.1", port, "u", "p",
                "Common", "mycert_v2", "mycert_v2",
                profiles, installOnly, false, hostnames);
    }

    private static SSLContext buildSelfSignedSslContext() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Principal dn = new X500Principal("CN=localhost");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 24L * 3600 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(1), notBefore, notAfter, dn, kp.getPublic());
        GeneralNames sans = new GeneralNames(new GeneralName[]{
                new GeneralName(GeneralName.iPAddress, "127.0.0.1"),
                new GeneralName(GeneralName.dNSName, "localhost"),
        });
        builder.addExtension(Extension.subjectAlternativeName, false, sans);
        X509Certificate cert = new JcaX509CertificateConverter()
                .getCertificate(builder.build(
                        new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate())));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, new char[0]);
        ks.setKeyEntry("self", kp.getPrivate(), new char[0], new X509Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        return ctx;
    }

    private F5BigIpCertRotator newRotator() {
        return new F5BigIpCertRotator(objectMapper);
    }

    @Test
    void rotate_happyPath_withDeclaredProfiles_patchesAndDetectsGroups() {
        router.addDeviceGroup("dg-ha", "sync-failover");
        // GET profile returns existing chain so PATCH is happy.
        router.setProfile("Common", "api-clientssl", "{\"certKeyChain\":[{\"name\":\"default\",\"cert\":\"/Common/old\"}]}");

        F5BigIpCertRotator.RotationResult result = newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(List.of("api-clientssl"), false, null),
                null);

        assertThat(result.profilesPatched()).containsExactly("api-clientssl");
        assertThat(result.deviceGroups()).containsExactly("dg-ha");
        assertThat(router.uploads).containsKeys("mycert_v2.crt", "mycert_v2.key");
        assertThat(router.savedConfig).isTrue();
        assertThat(router.loggedOut).isTrue();
    }

    @Test
    void rotate_installOnly_skipsProfileBindAndStillSaves() {
        F5BigIpCertRotator.RotationResult result = newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(List.of("ignored"), true, null),
                null);

        assertThat(result.profilesPatched()).isEmpty();
        assertThat(router.patches).isEmpty();
        assertThat(router.savedConfig).isTrue();
    }

    @Test
    void rotate_priorCertName_discoversAdditionalProfiles_andUnionsWithDeclared() {
        router.profileListBody = "{\"items\":["
                + "{\"name\":\"declared\",\"certKeyChain\":[{\"cert\":\"/Common/other\"}]},"
                + "{\"name\":\"discovered\",\"certKeyChain\":[{\"cert\":\"/Common/old_v1\"}]}"
                + "]}";
        router.setProfile("Common", "declared", "{\"certKeyChain\":[]}");
        router.setProfile("Common", "discovered", "{\"certKeyChain\":[]}");

        F5BigIpCertRotator.RotationResult result = newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(List.of("declared"), false, null),
                "old_v1");

        assertThat(result.profilesPatched()).containsExactlyInAnyOrder("declared", "discovered");
    }

    @Test
    void rotate_noProfilesNoFallback_throwsPermanentBootstrap() {
        router.profileListBody = "{\"items\":[]}";

        assertThatThrownBy(() -> newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(null, false, List.of("api.example.com")),
                null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_F5_NO_BOOTSTRAP"));

        // Logout still ran in the finally block.
        assertThat(router.loggedOut).isTrue();
    }

    @Test
    void rotate_noProfilesAndNoHostnames_throwsPermanent() {
        assertThatThrownBy(() -> newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(null, false, null),
                null))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void rotate_uploadFails_wrappedAsPermanent() {
        router.failUpload = true;

        assertThatThrownBy(() -> newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(List.of("api-clientssl"), false, null),
                null))
                .isInstanceOf(PermanentAgentException.class);
        assertThat(router.loggedOut).isTrue();
    }

    @Test
    void rotate_authFails_propagatesPermanent() {
        router.failLogin = true;

        assertThatThrownBy(() -> newRotator().rotate(
                "cert-pem", "key-pem",
                cfg(List.of("api-clientssl"), false, null),
                null))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void syncDeviceGroup_happyPath_callsSyncAndPolls() {
        router.syncStatusBody = "{\"x\":\"In Sync\"}";

        newRotator().syncDeviceGroup(cfg(List.of(), false, null), "dg-ha");

        assertThat(router.syncedDeviceGroup).isEqualTo("dg-ha");
        assertThat(router.loggedOut).isTrue();
    }

    @Test
    void syncDeviceGroup_pollError_propagatesTransient() {
        router.failSync = true;

        assertThatThrownBy(() -> newRotator().syncDeviceGroup(
                cfg(List.of(), false, null), "dg-ha"))
                .isInstanceOf(com.certping.agent.exception.TransientAgentException.class);
        assertThat(router.loggedOut).isTrue();
    }

    // -----------------------------------------------------------------------------------
    // Fake F5 router
    // -----------------------------------------------------------------------------------

    /** Minimal in-process F5 endpoint. Routes by path; each handler builds a JSON response. */
    private static class FakeF5Router implements HttpHandler {
        // Mutable expectations
        final Map<String, byte[]> uploads = new HashMap<>();
        final List<String> patches = new ArrayList<>();
        final Map<String, String> profileBodies = new HashMap<>();
        String profileListBody = "{\"items\":[]}";
        String syncStatusBody = "{\"x\":\"Standalone\"}";
        boolean savedConfig = false;
        boolean loggedOut = false;
        boolean failUpload = false;
        boolean failLogin = false;
        boolean failSync = false;
        String syncedDeviceGroup = null;

        // Device-group listing for detectDeviceGroups
        final List<Map<String, String>> deviceGroups = new ArrayList<>();

        void addDeviceGroup(String name, String type) {
            Map<String, String> dg = new HashMap<>();
            dg.put("name", name);
            dg.put("type", type);
            deviceGroups.add(dg);
        }

        void setProfile(String partition, String profile, String body) {
            profileBodies.put(partition + "/" + profile, body);
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            try {
                // Login
                if (path.equals("/mgmt/shared/authn/login")) {
                    if (failLogin) { respond(ex, 401, "{\"error\":\"denied\"}"); return; }
                    respond(ex, 200, "{\"token\":{\"token\":\"tok-abc\",\"timeout\":1200}}");
                    return;
                }
                // Token PATCH/DELETE
                if (path.startsWith("/mgmt/shared/authz/tokens/")) {
                    if (method.equals("DELETE")) loggedOut = true;
                    respond(ex, 200, "{}");
                    return;
                }
                // File upload
                if (path.startsWith("/mgmt/shared/file-transfer/uploads/")) {
                    if (failUpload) { respond(ex, 400, "{\"error\":\"bad\"}"); return; }
                    String filename = path.substring(path.lastIndexOf('/') + 1);
                    byte[] body = ex.getRequestBody().readAllBytes();
                    uploads.merge(filename, body, (a, b) -> {
                        byte[] r = new byte[a.length + b.length];
                        System.arraycopy(a, 0, r, 0, a.length);
                        System.arraycopy(b, 0, r, a.length, b.length);
                        return r;
                    });
                    respond(ex, 200, "{}");
                    return;
                }
                // Install cert/key
                if (path.equals("/mgmt/tm/sys/crypto/cert") || path.equals("/mgmt/tm/sys/crypto/key")) {
                    respond(ex, 200, "{}");
                    return;
                }
                // Save config
                if (path.equals("/mgmt/tm/sys/config")) {
                    savedConfig = true;
                    respond(ex, 200, "{}");
                    return;
                }
                // Profile list (with optional $filter query string)
                if (path.equals("/mgmt/tm/ltm/profile/client-ssl")) {
                    respond(ex, 200, profileListBody);
                    return;
                }
                // SSL cert object fetch (for SAN-based discovery): /mgmt/tm/sys/file/ssl-cert/~...
                if (path.startsWith("/mgmt/tm/sys/file/ssl-cert/")) {
                    respond(ex, 404, "{}");
                    return;
                }
                // Profile GET/PATCH: /mgmt/tm/ltm/profile/client-ssl/~Common~name
                if (path.startsWith("/mgmt/tm/ltm/profile/client-ssl/")) {
                    String tail = path.substring("/mgmt/tm/ltm/profile/client-ssl/".length());
                    String key = tail.replace("~", "/");
                    if (key.startsWith("/")) key = key.substring(1);
                    if (method.equals("PATCH")) {
                        patches.add(key);
                        respond(ex, 200, "{}");
                        return;
                    }
                    String body = profileBodies.getOrDefault(key, "{\"certKeyChain\":[]}");
                    respond(ex, 200, body);
                    return;
                }
                // Device groups (cm/device-group)
                if (path.equals("/mgmt/tm/cm/device-group")) {
                    StringBuilder sb = new StringBuilder("{\"items\":[");
                    for (int i = 0; i < deviceGroups.size(); i++) {
                        Map<String, String> dg = deviceGroups.get(i);
                        if (i > 0) sb.append(",");
                        sb.append("{\"name\":\"").append(dg.get("name"))
                                .append("\",\"type\":\"").append(dg.get("type")).append("\"}");
                    }
                    sb.append("]}");
                    respond(ex, 200, sb.toString());
                    return;
                }
                // Sync trigger (config-sync run-cmd)
                if (path.equals("/mgmt/tm/cm/config-sync")) {
                    if (failSync) { respond(ex, 500, "boom"); return; }
                    String body = new String(ex.getRequestBody().readAllBytes());
                    int i = body.indexOf("to-group ");
                    if (i >= 0) {
                        int end = body.indexOf("\"", i + "to-group ".length());
                        if (end > 0) syncedDeviceGroup = body.substring(i + "to-group ".length(), end);
                    }
                    respond(ex, 200, "{}");
                    return;
                }
                // Sync status (cm/sync-status)
                if (path.equals("/mgmt/tm/cm/sync-status")) {
                    if (failSync) { respond(ex, 500, "boom"); return; }
                    respond(ex, 200, syncStatusBody);
                    return;
                }
                respond(ex, 404, "{\"error\":\"unknown path " + path + "\"}");
            } catch (Exception e) {
                respond(ex, 500, "{\"error\":\"" + e.getMessage() + "\"}");
            }
        }

        private void respond(HttpExchange ex, int status, String body) throws IOException {
            // An unread request body makes the JDK server drop the connection, and the client's retry can
            // then land on it and fail as a network error instead of the status under test.
            ex.getRequestBody().readAllBytes();
            byte[] bytes = body.getBytes();
            ex.sendResponseHeaders(status, bytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        }
    }
}
