// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.Jwks;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The RSA keys behind access and refresh tokens. One private key signs; every published public key
 * verifies. Publishing a key before signing with it, and keeping the previous key published until
 * its tokens expire, is what lets the signing key rotate without logging anyone out.
 *
 * <p>Every rule is checked at construction, so a misconfigured environment fails to start.
 */
@Component
public class JwtSigningKeys {

    private static final int MIN_RSA_BITS = 2048;
    private static final List<String> PRIVATE_JWK_FIELDS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");
    static final String ALGORITHM = "RS256";

    private final String signingKeyId;
    private final RSAPrivateCrtKey signingKey;
    private final Map<String, RSAPublicKey> publishedKeys;
    private final String publicJwksJson;

    @Autowired
    public JwtSigningKeys(JwtProperties properties, ObjectMapper objectMapper) {
        this(properties.signingKeyId(), properties.signingPrivateKey(), properties.publishedKeys(), objectMapper);
    }

    JwtSigningKeys(String signingKeyId, String signingPrivateKeyPem, String publishedKeysJson, ObjectMapper objectMapper) {
        requireSettings(signingKeyId, signingPrivateKeyPem, publishedKeysJson);
        this.signingKeyId = signingKeyId.trim();
        this.publishedKeys = parsePublishedKeys(publishedKeysJson, objectMapper);
        this.signingKey = parsePrivateKey(signingPrivateKeyPem);

        RSAPublicKey signingPublicKey = publishedKeys.get(this.signingKeyId);
        if (signingPublicKey == null) {
            throw new IllegalStateException("JWT_SIGNING_KEY_ID '" + this.signingKeyId + "' is not in JWT_PUBLISHED_KEYS. "
                    + "Publish a key before signing with it, or verifiers will reject every new token.");
        }
        if (!signingPublicKey.getModulus().equals(signingKey.getModulus())
                || !signingPublicKey.getPublicExponent().equals(signingKey.getPublicExponent())) {
            throw new IllegalStateException("JWT_SIGNING_PRIVATE_KEY does not match the published key '" + this.signingKeyId + "'.");
        }
        this.publicJwksJson = toPublicJwksJson(publishedKeys, objectMapper);
    }

    public String signingKeyId() {
        return signingKeyId;
    }

    RSAPrivateCrtKey signingKey() {
        return signingKey;
    }

    public Optional<RSAPublicKey> publishedKey(String keyId) {
        return Optional.ofNullable(keyId).map(publishedKeys::get);
    }

    /** The JWKS served to verifiers, rebuilt from the parsed public keys rather than echoing the setting. */
    public String publicJwksJson() {
        return publicJwksJson;
    }

    private static void requireSettings(String keyId, String privateKey, String publishedKeys) {
        List<String> missing = new ArrayList<>();
        if (keyId == null || keyId.isBlank()) {
            missing.add("JWT_SIGNING_KEY_ID");
        }
        if (privateKey == null || privateKey.isBlank()) {
            missing.add("JWT_SIGNING_PRIVATE_KEY");
        }
        if (publishedKeys == null || publishedKeys.isBlank()) {
            missing.add("JWT_PUBLISHED_KEYS");
        }
        if (!missing.isEmpty()) {
            throw new IllegalStateException("JWT signing is not configured; missing " + String.join(", ", missing)
                    + ". scripts/jwt-keygen.sh prints a set for local use.");
        }
    }

    private static Map<String, RSAPublicKey> parsePublishedKeys(String json, ObjectMapper mapper) {
        rejectPrivateFields(json, mapper);
        Map<String, RSAPublicKey> keys = new LinkedHashMap<>();
        for (Jwk<?> jwk : Jwks.setParser().ignoreUnsupported(false).build().parse(json).getKeys()) {
            Key key = jwk.toKey();
            if (!(key instanceof RSAPublicKey publicKey)) {
                throw new IllegalStateException("JWT_PUBLISHED_KEYS must hold RSA public keys only; key '"
                        + jwk.getId() + "' is a " + key.getClass().getSimpleName() + ". It is served to anyone.");
            }
            if (jwk.getId() == null || jwk.getId().isBlank()) {
                throw new IllegalStateException("Every key in JWT_PUBLISHED_KEYS needs a kid.");
            }
            requireStrength(jwk.getId(), publicKey.getModulus().bitLength());
            if (keys.put(jwk.getId(), publicKey) != null) {
                throw new IllegalStateException("JWT_PUBLISHED_KEYS has two keys with kid '" + jwk.getId() + "'.");
            }
        }
        if (keys.isEmpty()) {
            throw new IllegalStateException("JWT_PUBLISHED_KEYS holds no keys.");
        }
        return Collections.unmodifiableMap(keys);
    }

    /**
     * jjwt treats an RSA JWK as public unless {@code d} is present and drops the other private
     * fields, yet a single prime is enough to rebuild the key. Checked on the raw JSON instead.
     */
    private static void rejectPrivateFields(String json, ObjectMapper mapper) {
        JsonNode keys;
        try {
            keys = mapper.readTree(json).path("keys");
        } catch (JacksonException e) {
            throw new IllegalStateException("JWT_PUBLISHED_KEYS is not valid JSON.");
        }
        for (JsonNode key : keys) {
            for (String field : PRIVATE_JWK_FIELDS) {
                if (key.has(field)) {
                    throw new IllegalStateException("JWT_PUBLISHED_KEYS must hold RSA public keys only; key '"
                            + key.path("kid").asString() + "' carries the private field '" + field + "'. It is served to anyone.");
                }
            }
        }
    }

    private static RSAPrivateCrtKey parsePrivateKey(String pem) {
        // Env files and some secret stores carry a PEM on one line with literal "\n" separators.
        String body = pem.replace("\\n", "\n")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        try {
            Key key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            if (!(key instanceof RSAPrivateCrtKey crtKey)) {
                throw new IllegalStateException("JWT_SIGNING_PRIVATE_KEY must be a PKCS#8 RSA key.");
            }
            requireStrength("signing key", crtKey.getModulus().bitLength());
            return crtKey;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            // The message never includes the key material.
            throw new IllegalStateException("JWT_SIGNING_PRIVATE_KEY is not a PKCS#8 PEM RSA private key.");
        }
    }

    private static void requireStrength(String keyId, int bits) {
        if (bits < MIN_RSA_BITS) {
            throw new IllegalStateException("JWT key '" + keyId + "' is " + bits + " bits; at least " + MIN_RSA_BITS + " are required.");
        }
    }

    private static String toPublicJwksJson(Map<String, RSAPublicKey> keys, ObjectMapper mapper) {
        try {
            ArrayNode array = mapper.createArrayNode();
            for (Map.Entry<String, RSAPublicKey> entry : keys.entrySet()) {
                String jwk = Jwks.json(Jwks.builder().key(entry.getValue()).id(entry.getKey())
                        .publicKeyUse("sig").algorithm(ALGORITHM).build());
                array.add(mapper.readTree(jwk));
            }
            return mapper.writeValueAsString(mapper.createObjectNode().set("keys", array));
        } catch (JacksonException e) {
            throw new IllegalStateException("Could not serialise the public JWKS.", e);
        }
    }
}
