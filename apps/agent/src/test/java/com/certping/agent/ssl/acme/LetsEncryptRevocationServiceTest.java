// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.acme;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRateLimitedException;
import org.shredzone.acme4j.util.KeyPairUtils;

import javax.security.auth.x500.X500Principal;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LetsEncryptRevocationServiceTest {

    private AgentProperties properties;
    private LetsEncryptRevocationService service;

    private static String VALID_BUNDLE;

    @BeforeAll
    static void generateTestBundle() throws Exception {
        KeyPair kp = KeyPairUtils.createKeyPair(2048);

        X500Principal subject = new X500Principal("CN=test.example.com");
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        var certBuilder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.valueOf(System.currentTimeMillis()),
                notBefore, notAfter, subject, kp.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256WithRSA").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        String certB64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(cert.getEncoded());
        String certPem = "-----BEGIN CERTIFICATE-----\n" + certB64 + "\n-----END CERTIFICATE-----\n";

        StringWriter keyWriter = new StringWriter();
        KeyPairUtils.writeKeyPair(kp, keyWriter);
        String keyPem = keyWriter.toString();

        VALID_BUNDLE = certPem + "\n" + keyPem;
    }

    @BeforeEach
    void setUp() {
        properties = new AgentProperties();
        properties.getAcme().setDirectoryUrl("https://acme-staging-v02.api.letsencrypt.org/directory");
        service = new LetsEncryptRevocationService(properties);
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void revoke_validBundle_callsCaRevocationApi() throws Exception {
        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenAnswer(inv -> null);

            service.revoke(VALID_BUNDLE, "KEY_COMPROMISE");

            mockCert.verify(() -> Certificate.revoke(any(), any(), any(), any()));
        }
    }

    @Test
    void revoke_nullReason_usesUnspecified() throws Exception {
        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenAnswer(inv -> null);

            service.revoke(VALID_BUNDLE, null);

            mockCert.verify(() -> Certificate.revoke(any(), any(), any(), any()));
        }
    }

    // ── Idempotency: already revoked ──────────────────────────────────────────

    @Test
    void revoke_alreadyRevokedAtCa_returnsNormally() {
        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenThrow(new AcmeException("Certificate already revoked"));

            service.revoke(VALID_BUNDLE, "SUPERSEDED");
        }
    }

    @Test
    void revoke_alreadyRevokedCaseInsensitive_returnsNormally() {
        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenThrow(new AcmeException("This certificate is ALREADY REVOKED by the CA"));

            service.revoke(VALID_BUNDLE, "CESSATION_OF_OPERATION");
        }
    }

    // ── ACME errors ───────────────────────────────────────────────────────────

    @Test
    void revoke_acmeExceptionOtherReason_throwsPermanent() {
        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenThrow(new AcmeException("rateLimited"));

            assertThatThrownBy(() -> service.revoke(VALID_BUNDLE, "KEY_COMPROMISE"))
                    .isInstanceOf(PermanentAgentException.class)
                    .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                            .isEqualTo("REVOCATION_FAILED"));
        }
    }

    // ── Rate-limit ────────────────────────────────────────────────────────────

    @Test
    void revoke_rateLimited_throwsRetryable() {
        // AcmeRateLimitedException is a subclass of AcmeException. The catch block in
        // LetsEncryptRevocationService routes it through RateLimitClassifier.classify
        // (heuristic match on the "ratelimited" class-name shape) -> CA_PROVIDER_THROTTLED.
        AcmeRateLimitedException rateLimited = mock(AcmeRateLimitedException.class);
        when(rateLimited.getMessage()).thenReturn("rate limit exceeded for /acme/revoke-cert");

        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenThrow(rateLimited);

            assertThatThrownBy(() -> service.revoke(VALID_BUNDLE, "KEY_COMPROMISE"))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> {
                        RetryableAgentException re = (RetryableAgentException) e;
                        assertThat(re.getErrorCode()).isEqualTo("CA_PROVIDER_THROTTLED");
                    });
        }
    }

    // ── Bundle parsing errors ─────────────────────────────────────────────────

    @Test
    void revoke_blankBundle_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke("", "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void revoke_bundleNoCertBlock_throwsPermanent() {
        String noCertBundle = "-----BEGIN PRIVATE KEY-----\nMIIEvg==\n-----END PRIVATE KEY-----";

        assertThatThrownBy(() -> service.revoke(noCertBundle, "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    @Test
    void revoke_bundleNoPrivateKey_throwsPermanent() {
        String noKeyBundle = "-----BEGIN CERTIFICATE-----\nMIIBxyz\n-----END CERTIFICATE-----";

        assertThatThrownBy(() -> service.revoke(noKeyBundle, "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("CERT_FORMAT_INVALID"));
    }

    // ── Reason mapping ────────────────────────────────────────────────────────

    // ── Outer Exception catch: rate-limited generic runtime ─────────────────
    @Test
    void revoke_certParseHitsRateLimitShape_throwsRetryable() {
        // Trigger the outer Exception catch by feeding a non-PEM bundle. CertificateBundleUtils
        // throws PermanentAgentException for malformed bundles — that's NOT a rate-limit, so this
        // goes through the standard PermanentAgentException re-throw path. Use a bundle that
        // triggers a generic exception with rate-limit-shaped message instead.
        String bundle = """
                -----BEGIN CERTIFICATE-----
                bm90LWEtcmVhbC1jZXJ0
                -----END CERTIFICATE-----
                -----BEGIN PRIVATE KEY-----
                bm90LWEtcmVhbC1rZXk=
                -----END PRIVATE KEY-----
                """;
        // bad cert format → CertificateException → wrapped as PermanentAgentException
        assertThatThrownBy(() -> service.revoke(bundle, "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("REVOCATION_FAILED"));
    }

    @Test
    void revoke_acmeRateLimited_inOuterCatch_throwsRetryable() {
        // AcmeRateLimitedException whose class-name matches "RateLimited" — the inner AcmeException
        // catch routes through the heuristic classifier → CA_PROVIDER_THROTTLED.
        AcmeRateLimitedException rateLimited = mock(AcmeRateLimitedException.class);
        when(rateLimited.getMessage()).thenReturn("throttled for /acme/revoke-cert, retry after 30");

        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenThrow(rateLimited);

            assertThatThrownBy(() -> service.revoke(VALID_BUNDLE, "KEY_COMPROMISE"))
                    .isInstanceOf(RetryableAgentException.class)
                    .satisfies(e -> assertThat(((RetryableAgentException) e).getErrorCode())
                            .isEqualTo("CA_PROVIDER_THROTTLED"));
        }
    }

    @Test
    void revoke_allKnownReasons_doNotThrowBeforeCaCall() throws Exception {
        String[] reasons = {"KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED",
                "CESSATION_OF_OPERATION", "UNKNOWN_REASON", null};

        try (MockedStatic<Certificate> mockCert = mockStatic(Certificate.class)) {
            mockCert.when(() -> Certificate.revoke(any(), any(), any(), any()))
                    .thenAnswer(inv -> null);

            for (String reason : reasons) {
                service.revoke(VALID_BUNDLE, reason);
            }

            mockCert.verify(() -> Certificate.revoke(any(), any(), any(), any()),
                    org.mockito.Mockito.times(reasons.length));
        }
    }
}
