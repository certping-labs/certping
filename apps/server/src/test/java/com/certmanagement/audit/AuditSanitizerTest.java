// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuditSanitizerTest {

    @ParameterizedTest
    @ValueSource(strings = {"password", "newPassword", "db_passwd", "passphrase", "clientSecret", "client-secret",
            "privateKey", "PRIVATE_KEY", "privKey", "connectionString", "agent.connection_string", "accessToken",
            "sasToken", "authCode", "eppCode", "apiKey", "api_key", "API-KEY", "accountKey", "storage_key", "sasUrl",
            "signature", "requestSignature", "keystore", "pkcs12Bundle", "tsigKey", "hmacKey", "authorization",
            "Authorization", "bearer", "bearerValue", "cookie", "setCookie", "gcpCredJson", "sig", "urlSig", "sas",
            "blobSas", "otp", "totp", "pem", "certPem", "pfx", "certPfx", "jwt", "idJwt"})
    void secretLookingNamesAreSecrets(String name) {
        assertThat(AuditSanitizer.isSecretName(name)).as(name).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"tokenPrefix", "credentialName", "provider", "keyVaultUri", "domain", "format", "email",
            "signedIn", "design", "assignee", "sasEnabled", "pemFormat", "jwtIssuer", "otpEnabled", "pfxFormat",
            "credentialJsonPath", "signatureAlgorithm"})
    void otherNamesAreNot(String name) {
        assertThat(AuditSanitizer.isSecretName(name)).as(name).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"-----BEGIN PRIVATE KEY-----\nMIIE...", "SharedAccessSignature sr=x&sig=abc&se=1",
            "https://acct.blob.core.windows.net/c?sv=2022&sig=abc%3D", "DefaultEndpointsProtocol=https;AccountKey=abc==",
            "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"})
    void secretLookingValuesAreRedactedWhateverTheirName(String value) {
        AuditEventRow row = row().details(new AuditDetails(List.of(new AuditChange("note", "plain", value)),
                Map.of("description", value))).build();

        AuditDetails details = AuditSanitizer.sanitize(row).details();

        assertThat(details.changes()).containsExactly(new AuditChange("note", "plain", AuditSanitizer.REDACTED));
        assertThat(details.attributes()).containsEntry("description", AuditSanitizer.REDACTED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"design=modern", "Signed in with SSO", "eyJ alone is not a token", "BEGIN of the month"})
    void benignValuesStay(String value) {
        assertThat(AuditSanitizer.isSecretValue(value)).as(value).isFalse();
    }

    @Test
    void redactsSecretChangesAndAttributesButKeepsTheirNames() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("apiKey", "sk_live_123");
        attributes.put("provider", "Azure");
        AuditEventRow row = row().details(new AuditDetails(
                List.of(new AuditChange("clientSecret", "old-secret", "new-secret"), new AuditChange("name", "a", "b")),
                attributes)).build();

        AuditDetails details = AuditSanitizer.sanitize(row).details();

        assertThat(details.changes()).containsExactly(
                new AuditChange("clientSecret", AuditSanitizer.REDACTED, AuditSanitizer.REDACTED),
                new AuditChange("name", "a", "b"));
        assertThat(details.attributes()).containsExactly(
                Map.entry("apiKey", AuditSanitizer.REDACTED), Map.entry("provider", "Azure"));
    }

    @Test
    void capsFieldsInUtf8BytesWithoutSplittingACharacter() {
        String euros = "€".repeat(400); // 3 bytes each
        AuditEventRow row = row().summary("s".repeat(5000)).userAgent(euros).resourceName(euros)
                .details(new AuditDetails(List.of(), Map.of("note", "n".repeat(5000)))).build();

        AuditEventRow clean = AuditSanitizer.sanitize(row);

        assertThat(bytes(clean.summary())).isEqualTo(AuditSanitizer.TEXT_MAX);
        assertThat(clean.userAgent()).isEqualTo("€".repeat(85)); // 255 bytes; a 86th would make 258
        assertThat(clean.resourceName()).isEqualTo(clean.userAgent());
        assertThat(bytes(clean.details().attributes().get("note"))).isEqualTo(AuditSanitizer.VALUE_MAX);
    }

    @Test
    void removesNulAndControlCharactersAndReplacesUnpairedSurrogates() {
        AuditEventRow row = row().summary("a\u0000b\u0007c\td\ne\r").resourceName("x\uD800y\uDC00z😀").build();

        AuditEventRow clean = AuditSanitizer.sanitize(row);

        assertThat(clean.summary()).isEqualTo("abc\td\ne");
        assertThat(clean.resourceName()).isEqualTo("x�y�z😀");
    }

    @Test
    void leavesNullsAndShortValuesAlone() {
        AuditEventRow row = row().build();

        assertThat(AuditSanitizer.sanitize(row)).isEqualTo(row);
    }

    private static int bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    static AuditEventRow.AuditEventRowBuilder row() {
        return AuditEventRow.builder()
                .occurredAt(Instant.parse("2026-10-07T10:00:00Z"))
                .visibility(AuditVisibility.INTERNAL)
                .actorType(AuditActorType.SYSTEM)
                .action("TEST")
                .resourceType("AUDIT")
                .outcome(AuditOutcome.SUCCESS)
                .summary("Did a thing");
    }
}
