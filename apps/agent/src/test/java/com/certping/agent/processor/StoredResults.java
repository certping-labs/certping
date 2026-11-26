// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.IssuanceCheckpoint;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.message.CertIssuanceResponse;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.CertificateMetadataExtractor;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import tools.jackson.core.JacksonException;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A certificate stored in the agent's vault, and the stored result that describes it. */
final class StoredResults {

    static final String HANDLE = "https://kv.vault.azure.net/secrets/xref-1";
    static final String BUNDLE = pemBundle();
    /** The serial of the certificate in {@link #BUNDLE}, as the agent writes serials. */
    static final String LEAF_SERIAL = "1";

    private StoredResults() {
    }

    /** The stored result of {@code certificateXref}, describing the certificate in {@link #BUNDLE}. */
    static String storedResult(String certificateXref) {
        return storedResult(certificateXref, HANDLE, fingerprint());
    }

    static String storedResult(String certificateXref, String handle, String fingerprint) {
        CertIssuanceResponse response = CertIssuanceResponse.builder()
                .requestId("req-1")
                .correlationId("corr-1")
                .organizationId("organization-1")
                .certificateXref(certificateXref)
                .status("ISSUED")
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle(handle)
                .fingerprintSha256(fingerprint)
                .serialNumber("ABCD")
                .build();
        try {
            return JsonMapper.builderWithJackson2Defaults().build().writeValueAsString(response);
        } catch (JacksonException e) {
            throw new IllegalStateException(e);
        }
    }

    /** {@code context} delivers a message carrying {@code response} as a stored result. */
    static void deliverStored(InboundContext context, String response) {
        InboundMessage message = mock(InboundMessage.class);
        when(message.getApplicationProperties()).thenReturn(new HashMap<>(
                IssuanceCheckpoint.storedResult("LETS_ENCRYPT", response).toAppProperties()));
        when(context.getMessage()).thenReturn(message);
    }

    /** {@code secretStore} holds {@link #BUNDLE} at {@link #HANDLE}, in this agent's own vault. */
    static void storeMatchingCertificate(SecretStore secretStore) {
        when(secretStore.isOwnedByThisAgent(HANDLE)).thenReturn(true);
        when(secretStore.read(HANDLE)).thenReturn(BUNDLE);
    }

    static String fingerprint() {
        try {
            return CertificateMetadataExtractor.sha256Fingerprint(CertificateMetadataExtractor.firstCertificate(BUNDLE));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String pemBundle() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generator.generateKeyPair();
            X500Principal subject = new X500Principal("CN=example.com");
            X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                    new JcaX509v3CertificateBuilder(subject, BigInteger.ONE, new Date(),
                            new Date(System.currentTimeMillis() + 86_400_000L), subject, keyPair.getPublic())
                            .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
            String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n"
                    + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
