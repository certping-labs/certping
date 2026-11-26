// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import com.certping.agent.exception.PermanentAgentException;
import lombok.extern.slf4j.Slf4j;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;

/**
 * Builds the long-lived {@link HttpClient}s for one EJBCA connection.
 *
 * <p>Two are needed, and conflating them is a real trap. The EJBCA client pins its truststore to
 * {@code serverCaChainPem} because EJBCA's TLS certificate is normally issued by a private
 * ManagementCA. That truststore <em>replaces</em> the JDK defaults, so reusing it to reach a
 * public IdP token endpoint would fail PKIX validation — which is exactly the shape of a
 * production OAuth deployment.
 */
@Slf4j
final class EjbcaTlsContextFactory {

    private EjbcaTlsContextFactory() {
    }

    /**
     * Client for the IdP token endpoint. Uses the JDK default trust store: the token URL is a
     * different host from EJBCA and is normally publicly trusted, so EJBCA's private CA chain is
     * both wrong and insufficient for it.
     */
    static HttpClient createIdpHttpClient(Duration timeout) {
        return HttpClient.newBuilder()
                .connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** Client for EJBCA itself: client certificate when using mTLS, pinned truststore when given. */
    static HttpClient createHttpClient(EjbcaCredentials credentials, Duration timeout) {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers(credentials), trustManagers(credentials), null);

            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(timeout)
                    // See EjbcaErrorMapper: a followed redirect would drop a POST body.
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();
        } catch (PermanentAgentException e) {
            throw e;
        } catch (Exception e) {
            throw new PermanentAgentException("EJBCA_TLS_CONFIG_INVALID",
                    "Failed to build the EJBCA TLS context — check clientP12Base64, "
                            + "clientP12Password and serverCaChainPem: " + e.getMessage(), e);
        }
    }

    /** Null on the OAuth path: the bearer token is the credential, so no client cert is presented. */
    private static javax.net.ssl.KeyManager[] keyManagers(EjbcaCredentials credentials)
            throws Exception {
        if (credentials.authMethod() != EjbcaCredentials.AuthMethod.CLIENT_CERT) {
            return null;
        }
        char[] password = credentials.clientP12Password().toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(
                Base64.getDecoder().decode(credentials.clientP12Base64())), password);

        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, password);
        return factory.getKeyManagers();
    }

    /**
     * Null means the JDK default trust store, which is right when EJBCA presents a publicly
     * trusted certificate. It must never mean "trust everything" — EJBCA's TLS certificate is
     * normally issued by ManagementCA, and the fix for that is to supply the chain, not to stop
     * checking.
     */
    private static javax.net.ssl.TrustManager[] trustManagers(EjbcaCredentials credentials)
            throws Exception {
        if (credentials.serverCaChainPem() == null) {
            return null;
        }
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(
                new ByteArrayInputStream(
                        credentials.serverCaChainPem().getBytes(StandardCharsets.UTF_8)));
        if (certificates.isEmpty()) {
            throw new PermanentAgentException("EJBCA_TLS_CONFIG_INVALID",
                    "serverCaChainPem contained no certificates");
        }

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        int index = 0;
        for (Certificate certificate : certificates) {
            trustStore.setCertificateEntry("ejbca-ca-" + index++, certificate);
            if (certificate instanceof X509Certificate x509) {
                log.debug("EJBCA truststore entry: {}", x509.getSubjectX500Principal().getName());
            }
        }

        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        return factory.getTrustManagers();
    }
}
