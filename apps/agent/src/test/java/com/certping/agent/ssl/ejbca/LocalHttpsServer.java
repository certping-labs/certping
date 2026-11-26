// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A throwaway HTTPS server for driver tests.
 *
 * <p>Real TLS rather than a mocked {@code HttpClient}: the driver's trust wiring, hostname
 * verification and redirect policy are behaviours worth exercising, and a mock would assert only
 * that we call the methods we wrote.
 */
final class LocalHttpsServer implements AutoCloseable {

    private final HttpsServer server;
    private final String caPem;
    private final AtomicInteger callCount = new AtomicInteger();
    private final List<String> paths = new CopyOnWriteArrayList<>();

    /** Responses are served in order; the last one repeats once the queue is drained. */
    private final List<Response> responses = new CopyOnWriteArrayList<>();

    record Response(int status, String body, String locationHeader) {
        static Response of(int status, String body) {
            return new Response(status, body, null);
        }
    }

    LocalHttpsServer() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        var subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, "localhost").build();
        var holder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE,
                new Date(System.currentTimeMillis() - 3_600_000),
                new Date(System.currentTimeMillis() + 3_600_000),
                subject, keyPair.getPublic())
                // Without a matching SAN the JDK client rejects the connection — which is the
                // hostname verification we rely on and deliberately never disable.
                .addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")))
                .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                        .build(keyPair.getPrivate()));
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(holder);

        caPem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("server", keyPair.getPrivate(), new char[0],
                new java.security.cert.Certificate[]{certificate});
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);

        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
        server.createContext("/", exchange -> {
            paths.add(exchange.getRequestURI().getPath());
            Response response = nextResponse();
            byte[] body = response.body().getBytes();
            if (response.locationHeader() != null) {
                exchange.getResponseHeaders().add("Location", response.locationHeader());
            }
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(response.status(), body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    private Response nextResponse() {
        int index = callCount.getAndIncrement();
        return responses.get(Math.min(index, responses.size() - 1));
    }

    LocalHttpsServer respond(Response... queued) {
        responses.clear();
        responses.addAll(List.of(queued));
        callCount.set(0);
        paths.clear();
        return this;
    }

    String baseUrl() {
        return "https://localhost:" + server.getAddress().getPort();
    }

    String caPem() {
        return caPem;
    }

    int callCount() {
        return callCount.get();
    }

    List<String> requestedPaths() {
        return List.copyOf(paths);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
