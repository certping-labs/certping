// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.exception.PermanentAgentException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;

final class SmallstepTlsContextFactory {
    private SmallstepTlsContextFactory() {}

    static HttpClient create(String rootCaPem, Duration timeout) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certificates = factory.generateCertificates(
                    new ByteArrayInputStream(rootCaPem.getBytes(StandardCharsets.US_ASCII)));
            if (certificates.isEmpty()) throw new IllegalArgumentException("rootCaPem contains no certificate");
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            int index = 0;
            for (java.security.cert.Certificate certificate : certificates) {
                trust.setCertificateEntry("smallstep-root-" + index++, (X509Certificate) certificate);
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            managers.init(trust);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, managers.getTrustManagers(), null);
            return HttpClient.newBuilder().sslContext(ssl).connectTimeout(timeout)
                    .followRedirects(HttpClient.Redirect.NEVER).build();
        } catch (Exception exception) {
            throw new PermanentAgentException("SMALLSTEP_TRUST_INVALID",
                    "Could not build Smallstep TLS trust from rootCaPem", exception);
        }
    }
}
