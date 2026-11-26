// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.intune;

import com.certping.agent.scep.ChallengeValidationException;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.boot.restclient.RestTemplateBuilder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Opt-in live proof for whether Intune ValidateRequest protects the outer DeviceId field.
 *
 * <p>The tampered request is deliberately sent first. If Microsoft rejects it, the unchanged
 * control is sent with the same freshly generated key and transaction id. Only
 * {@code tampered=REJECTED, control=ACCEPTED} proves coverage. A control rejection is
 * inconclusive (usually an expired or previously consumed challenge), never treated as proof.
 */
@Tag("live-intune")
class IntuneDeviceIdTamperProbeTest {
    private static final String CHALLENGE_PATH_PROPERTY =
            "intune.device-id-probe.challenge-path";
    private static final String CALLER_INFO = "CertPing-Agent/DeviceIdTamperProbe";

    @Test
    void provesDeviceIdCoverageUsingAFreshUnconsumedChallenge() throws Exception {
        String challengePath = System.getProperty(CHALLENGE_PATH_PROPERTY);
        assumeTrue(challengePath != null && !challengePath.isBlank(),
                "Set -D" + CHALLENGE_PATH_PROPERTY + "=/path/to/fresh.challenge.xml");
        String tenantId = requiredEnvironment("AZURE_TENANT_ID");
        String clientId = requiredEnvironment("AZURE_INTUNE_CLIENT_ID");
        String clientSecret = requiredEnvironment("AZURE_INTUNE_CLIENT_SECRET");

        String controlXml = Files.readString(Path.of(challengePath));
        String tamperedXml = replaceDeviceId(controlXml, UUID.randomUUID().toString());
        KeyPair keyPair = rsaKeyPair();
        String transactionId = HexFormat.of().withUpperCase().formatHex(
                MessageDigest.getInstance("SHA-1").digest(keyPair.getPublic().getEncoded()));

        IntuneScepClient client = new IntuneScepClient(new RestTemplateBuilder());
        String graphToken = client.acquireToken(
                tenantId, clientId, clientSecret, IntuneScepClient.GRAPH_SCOPE);
        String manageToken = client.acquireToken(
                tenantId, clientId, clientSecret, IntuneScepClient.MANAGE_SCOPE);
        String serviceUrl = client.discoverValidationServiceUrl(graphToken);

        Outcome tampered = validate(client, serviceUrl, manageToken, transactionId,
                csrBase64(keyPair, tamperedXml));
        Outcome control = tampered == Outcome.REJECTED
                ? validate(client, serviceUrl, manageToken, transactionId,
                        csrBase64(keyPair, controlXml))
                : Outcome.NOT_RUN;

        assertThat(tampered)
                .as("A tampered DeviceId must be rejected")
                .isEqualTo(Outcome.REJECTED);
        assertThat(control)
                .as("The unchanged control must be accepted; rejection is inconclusive")
                .isEqualTo(Outcome.ACCEPTED);
    }

    private static Outcome validate(
            IntuneScepClient client,
            String serviceUrl,
            String token,
            String transactionId,
            String csrBase64) {
        try {
            client.validateRequest(serviceUrl, token, transactionId, csrBase64, CALLER_INFO);
            return Outcome.ACCEPTED;
        } catch (ChallengeValidationException exception) {
            return Outcome.REJECTED;
        }
    }

    private static String csrBase64(KeyPair keyPair, String challengeXml) throws Exception {
        String challenge = Base64.getEncoder().encodeToString(
                challengeXml.getBytes(StandardCharsets.UTF_8));
        var builder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name("CN=certping-deviceid-tamper-probe"), keyPair.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(challenge));
        byte[] csr = builder.build(new JcaContentSignerBuilder("SHA512withRSA")
                .build(keyPair.getPrivate())).getEncoded();
        return Base64.getEncoder().encodeToString(csr);
    }

    private static String replaceDeviceId(String xml, String replacement) {
        String start = "<DeviceId>";
        String end = "</DeviceId>";
        int startIndex = xml.indexOf(start);
        int endIndex = xml.indexOf(end);
        if (startIndex < 0 || endIndex <= startIndex
                || xml.indexOf(start, startIndex + start.length()) >= 0) {
            throw new IllegalArgumentException("Challenge must contain exactly one DeviceId");
        }
        return xml.substring(0, startIndex + start.length()) + replacement
                + xml.substring(endIndex);
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String requiredEnvironment(String name) {
        String value = System.getenv(name);
        assumeTrue(value != null && !value.isBlank(), name + " must be set");
        return value;
    }

    private enum Outcome {
        ACCEPTED,
        REJECTED,
        NOT_RUN
    }
}
