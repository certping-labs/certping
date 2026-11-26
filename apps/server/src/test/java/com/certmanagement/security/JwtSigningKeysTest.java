// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.security.Jwks;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtSigningKeysTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();
    private static final KeyPair CURRENT = JwtTestKeys.rsa(2048);
    private static final KeyPair NEXT = JwtTestKeys.rsa(2048);

    @Test
    void loadsTheSigningKeyAndEveryPublishedKey() {
        JwtSigningKeys keys = new JwtSigningKeys("k1", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", CURRENT), JwtTestKeys.publicJwk("k2", NEXT)), MAPPER);

        assertThat(keys.signingKeyId()).isEqualTo("k1");
        assertThat(keys.publishedKey("k1")).contains((java.security.interfaces.RSAPublicKey) CURRENT.getPublic());
        assertThat(keys.publishedKey("k2")).contains((java.security.interfaces.RSAPublicKey) NEXT.getPublic());
        assertThat(keys.publishedKey("unknown")).isEmpty();
    }

    @Test
    void refusesToSignWithAKeyThatIsNotPublished() {
        assertThatThrownBy(() -> new JwtSigningKeys("k2", JwtTestKeys.privatePem(NEXT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", CURRENT)), MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("k2")
                .hasMessageContaining("JWT_PUBLISHED_KEYS");
    }

    @Test
    void refusesAPrivateKeyThatDoesNotMatchItsPublishedHalf() {
        assertThatThrownBy(() -> new JwtSigningKeys("k1", JwtTestKeys.privatePem(NEXT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", CURRENT)), MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("does not match");
    }

    /** The published set is served to anyone; private material in it would be a key leak. */
    @Test
    void refusesPrivateKeyMaterialInThePublishedSet() {
        String privateJwk = Jwks.UNSAFE_JSON(Jwks.builder().key((RSAPrivateKey) CURRENT.getPrivate())
                .publicKey((java.security.interfaces.RSAPublicKey) CURRENT.getPublic()).id("k1").build());

        assertThatThrownBy(() -> new JwtSigningKeys("k1", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(privateJwk), MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("public keys only");
    }

    @Test
    void refusesKeysShorterThan2048Bits() {
        KeyPair weak = JwtTestKeys.rsa(1024);
        assertThatThrownBy(() -> new JwtSigningKeys("k1", JwtTestKeys.privatePem(weak),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", weak)), MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("2048");
    }

    @Test
    void refusesMissingSettingsAndNamesEveryOne() {
        assertThatThrownBy(() -> new JwtSigningKeys(" ", null, "", MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_SIGNING_KEY_ID")
                .hasMessageContaining("JWT_SIGNING_PRIVATE_KEY")
                .hasMessageContaining("JWT_PUBLISHED_KEYS");
    }

    @Test
    void servesOnlyPublicParameters() throws Exception {
        JwtSigningKeys keys = new JwtSigningKeys("k1", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", CURRENT), JwtTestKeys.publicJwk("k2", NEXT)), MAPPER);

        JsonNode served = MAPPER.readTree(keys.publicJwksJson());

        assertThat(served.get("keys")).hasSize(2);
        for (JsonNode key : served.get("keys")) {
            assertThat(key.propertyNames().iterator()).toIterable().containsExactlyInAnyOrder("kty", "kid", "use", "alg", "n", "e");
            assertThat(key.get("alg").asString()).isEqualTo("RS256");
            assertThat(key.get("use").asString()).isEqualTo("sig");
        }
    }
    @Test
    void acceptsAPemCarriedOnOneLineWithEscapedNewlines() {
        String oneLine = JwtTestKeys.privatePem(CURRENT).replace("\n", "\\n");

        JwtSigningKeys keys = new JwtSigningKeys("k1", oneLine,
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k1", CURRENT)), MAPPER);

        assertThat(keys.signingKeyId()).isEqualTo("k1");
    }

    /** The keygen script is how environments get keys; its output must load exactly as printed. */
    @Test
    void acceptsWhatTheKeygenScriptPrints() throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(
                new ProcessBuilder("openssl", "version").start().waitFor() == 0, "openssl not installed");
        Process process = new ProcessBuilder("bash", "scripts/jwt-keygen.sh", "script-kid").start();
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(process.waitFor()).isZero();

        java.util.Map<String, String> env = new java.util.HashMap<>();
        for (String line : output.split("\n")) {
            int eq = line.indexOf('=');
            String value = line.substring(eq + 1);
            if (value.length() >= 2 && (value.startsWith("'") && value.endsWith("'") || value.startsWith("\"") && value.endsWith("\""))) {
                value = value.substring(1, value.length() - 1);
            }
            env.put(line.substring(0, eq), value);
        }

        JwtSigningKeys keys = new JwtSigningKeys(env.get("JWT_SIGNING_KEY_ID"), env.get("JWT_SIGNING_PRIVATE_KEY"),
                env.get("JWT_PUBLISHED_KEYS"), MAPPER);

        assertThat(keys.signingKeyId()).isEqualTo("script-kid");
        assertThat(env).containsEntry("JWT_AUDIENCE", "certping-api");
    }
    /** jjwt parses an RSA JWK as public when only d is absent, so the primes would slip through. */
    @Test
    void refusesPrivatePrimesEvenWithoutD() throws Exception {
        tools.jackson.databind.node.ObjectNode full = (tools.jackson.databind.node.ObjectNode) MAPPER.readTree(
                Jwks.UNSAFE_JSON(Jwks.builder().key((RSAPrivateKey) CURRENT.getPrivate())
                        .publicKey((java.security.interfaces.RSAPublicKey) CURRENT.getPublic()).id("k1").build()));
        full.remove("d");

        assertThatThrownBy(() -> new JwtSigningKeys("k1", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(MAPPER.writeValueAsString(full)), MAPPER))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("public keys only");
    }
}
