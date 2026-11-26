// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtTokenProviderTest {

    private static final ObjectMapper MAPPER = JsonMapper.builderWithJackson2Defaults().build();
    private static final KeyPair OLD = JwtTestKeys.rsa(2048);
    private static final KeyPair CURRENT = JwtTestKeys.rsa(2048);
    private static final KeyPair ATTACKER = JwtTestKeys.rsa(2048);
    private static final String ISSUER = "https://api.certping.test";
    private static final String AUDIENCE = "certping-api";

    private final JwtTokenProvider provider = provider("k-current", CURRENT,
            JwtTestKeys.publicJwk("k-old", OLD), JwtTestKeys.publicJwk("k-current", CURRENT));

    private static JwtTokenProvider provider(String signingKid, KeyPair signing, String... published) {
        JwtSigningKeys keys = new JwtSigningKeys(signingKid, JwtTestKeys.privatePem(signing),
                JwtTestKeys.jwks(published), MAPPER);
        return new JwtTokenProvider(keys, new JwtProperties(ISSUER, AUDIENCE, signingKid, null, null, 900_000L, 604_800_000L));
    }

    @Test
    void accessTokenRoundTripsEveryClaim() {
        String token = provider.generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);

        AccessToken parsed = provider.parseAccessToken(token).orElseThrow();

        assertThat(parsed.email()).isEqualTo("u@example.com");
        assertThat(parsed.userId()).isEqualTo(7);
        assertThat(parsed.organizationId()).isEqualTo(42L);
        assertThat(parsed.roles()).containsExactly("ORG_ADMIN");
        assertThat(parsed.permissions()).containsExactly("certificate:read");
        assertThat(parsed.authMethod()).isEqualTo(JwtClaims.AUTH_METHOD_LOCAL);
        assertThat(parsed.jti()).isNotBlank();
        assertThat(parsed.expiresAt()).isAfter(Instant.now());
    }

    @Test
    void accessTokenCarriesKidIssuerAudienceAndType() throws Exception {
        String token = provider.generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);
        String[] parts = token.split("\\.");
        var header = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[0]));
        var body = MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));

        assertThat(header.get("alg").asString()).isEqualTo("RS256");
        assertThat(header.get("kid").asString()).isEqualTo("k-current");
        assertThat(body.get("iss").asString()).isEqualTo(ISSUER);
        assertThat(body.get("aud").toString()).contains(AUDIENCE);
        assertThat(body.get(JwtClaims.TOKEN_TYPE).asString()).isEqualTo(JwtClaims.TOKEN_TYPE_ACCESS);
    }

    /** A refresh token presented as a bearer token used to authenticate with no roles. */
    @Test
    void aRefreshTokenIsNeverAnAccessTokenAndViceVersa() {
        String refresh = provider.generateRefreshToken(user(), org());
        String access = provider.generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);

        assertThat(provider.parseAccessToken(refresh)).isEmpty();
        assertThat(provider.parseRefreshToken(access)).isEmpty();
        assertThat(provider.parseRefreshToken(refresh)).isPresent();
    }

    @Test
    void refreshTokenRoundTrips() {
        RefreshToken parsed = provider.parseRefreshToken(provider.generateRefreshToken(user(), org())).orElseThrow();

        assertThat(parsed.email()).isEqualTo("u@example.com");
        assertThat(parsed.userId()).isEqualTo(7);
        assertThat(parsed.organizationId()).isEqualTo(42L);
        assertThat(parsed.jti()).isNotBlank();
    }

    /** A token signed with a key that is still published keeps working after the signing key rotates. */
    @Test
    void tokensFromAPreviouslyUsedKeyStillVerifyAfterRotation() {
        JwtTokenProvider beforeRotation = provider("k-old", OLD,
                JwtTestKeys.publicJwk("k-old", OLD), JwtTestKeys.publicJwk("k-current", CURRENT));
        String issuedBefore = beforeRotation.generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);

        assertThat(provider.parseAccessToken(issuedBefore)).isPresent();
    }

    @Test
    void aKeyThatIsNoLongerPublishedNoLongerVerifies() {
        String issuedWithOld = provider("k-old", OLD, JwtTestKeys.publicJwk("k-old", OLD))
                .generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);
        JwtTokenProvider afterRetirement = provider("k-current", CURRENT, JwtTestKeys.publicJwk("k-current", CURRENT));

        assertThat(afterRetirement.parseAccessToken(issuedWithOld)).isEmpty();
    }

    @Test
    void rejectsAlgNone() {
        String unsigned = b64("{\"alg\":\"none\",\"kid\":\"k-current\"}") + "." + b64(validClaimsJson()) + ".";

        assertThat(provider.parseAccessToken(unsigned)).isEmpty();
    }

    /** Algorithm confusion: HS256 keyed with the public key's bytes, which anyone can fetch from the JWKS. */
    @Test
    void rejectsHs256SignedWithThePublicKey() {
        String forged = Jwts.builder()
                .header().keyId("k-current").and()
                .issuer(ISSUER).audience().add(AUDIENCE).and()
                .subject("attacker@example.com")
                .claim(JwtClaims.TOKEN_TYPE, JwtClaims.TOKEN_TYPE_ACCESS)
                .expiration(Date.from(Instant.now().plusSeconds(600)))
                .signWith(Keys.hmacShaKeyFor(CURRENT.getPublic().getEncoded()), Jwts.SIG.HS256)
                .compact();

        assertThat(provider.parseAccessToken(forged)).isEmpty();
    }

    /** The kid only selects a key; copying a published kid onto a token signed elsewhere proves nothing. */
    @Test
    void rejectsATokenSignedByAnUnpublishedKeyUnderAPublishedKid() {
        String forged = signedWith(ATTACKER, "k-current", ISSUER, AUDIENCE, JwtClaims.TOKEN_TYPE_ACCESS, 600);

        assertThat(provider.parseAccessToken(forged)).isEmpty();
    }

    @Test
    void rejectsUnknownOrMissingKid() {
        assertThat(provider.parseAccessToken(signedWith(CURRENT, "k-unknown", ISSUER, AUDIENCE, JwtClaims.TOKEN_TYPE_ACCESS, 600))).isEmpty();
        assertThat(provider.parseAccessToken(signedWith(CURRENT, null, ISSUER, AUDIENCE, JwtClaims.TOKEN_TYPE_ACCESS, 600))).isEmpty();
    }

    @Test
    void rejectsWrongIssuerAudienceOrType() {
        assertThat(provider.parseAccessToken(signedWith(CURRENT, "k-current", "https://evil.test", AUDIENCE, JwtClaims.TOKEN_TYPE_ACCESS, 600))).isEmpty();
        assertThat(provider.parseAccessToken(signedWith(CURRENT, "k-current", ISSUER, "some-other-api", JwtClaims.TOKEN_TYPE_ACCESS, 600))).isEmpty();
        assertThat(provider.parseAccessToken(signedWith(CURRENT, "k-current", ISSUER, AUDIENCE, null, 600))).isEmpty();
    }

    @Test
    void rejectsExpiredAndTamperedTokens() {
        assertThat(provider.parseAccessToken(signedWith(CURRENT, "k-current", ISSUER, AUDIENCE, JwtClaims.TOKEN_TYPE_ACCESS, -120))).isEmpty();

        String token = provider.generateAccessToken(user(), org(), JwtClaims.AUTH_METHOD_LOCAL);
        String[] parts = token.split("\\.");
        String tampered = parts[0] + "." + b64(validClaimsJson()) + "." + parts[2];
        assertThat(provider.parseAccessToken(tampered)).isEmpty();
    }

    @Test
    void rejectsGarbageWithoutThrowing() {
        assertThat(provider.parseAccessToken("")).isEmpty();
        assertThat(provider.parseAccessToken(null)).isEmpty();
        assertThat(provider.parseAccessToken("not.a.jwt")).isEmpty();
    }

    private static String signedWith(KeyPair pair, String kid, String issuer, String audience, String type, long ttlSeconds) {
        var builder = Jwts.builder();
        if (kid != null) {
            builder.header().keyId(kid).and();
        }
        builder.issuer(issuer).audience().add(audience).and()
                .subject("u@example.com")
                .claim(JwtClaims.USER_ID, 7)
                .expiration(Date.from(Instant.now().plusSeconds(ttlSeconds)));
        if (type != null) {
            builder.claim(JwtClaims.TOKEN_TYPE, type);
        }
        return builder.signWith(pair.getPrivate(), Jwts.SIG.RS256).compact();
    }

    private static String validClaimsJson() {
        long exp = Instant.now().plusSeconds(600).getEpochSecond();
        return "{\"iss\":\"" + ISSUER + "\",\"aud\":\"" + AUDIENCE + "\",\"sub\":\"attacker@example.com\",\"type\":\"access\",\"exp\":" + exp + "}";
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static User user() {
        User user = mock(User.class);
        when(user.getId()).thenReturn(7);
        when(user.getEmail()).thenReturn("u@example.com");
        when(user.getRoleNames()).thenReturn(java.util.Set.of("ORG_ADMIN"));
        when(user.getEffectivePermissionNames()).thenReturn(java.util.Set.of("certificate:read"));
        return user;
    }

    private static Organization org() {
        Organization org = mock(Organization.class);
        when(org.getId()).thenReturn(42L);
        when(org.getName()).thenReturn("Acme");
        when(org.getOrgType()).thenReturn("B2B");
        return org;
    }
    /** Only RS256 verifies, even for a token genuinely signed by a published key. */
    @Test
    void rejectsOtherRsaAlgorithmsSignedWithAPublishedKey() {
        for (var alg : java.util.List.of(Jwts.SIG.RS512, Jwts.SIG.PS256)) {
            String token = Jwts.builder()
                    .header().keyId("k-current").and()
                    .issuer(ISSUER).audience().add(AUDIENCE).and()
                    .subject("u@example.com")
                    .claim(JwtClaims.TOKEN_TYPE, JwtClaims.TOKEN_TYPE_ACCESS)
                    .expiration(Date.from(Instant.now().plusSeconds(600)))
                    .signWith(CURRENT.getPrivate(), alg)
                    .compact();

            assertThat(provider.parseAccessToken(token)).as(alg.getId()).isEmpty();
        }
    }

    /** An unset variable binds as the literal placeholder text; that must fail, not become the issuer. */
    @Test
    void refusesAnUnresolvedIssuerPlaceholder() {
        JwtSigningKeys keys = new JwtSigningKeys("k-current", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k-current", CURRENT)), MAPPER);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new JwtTokenProvider(keys,
                        new JwtProperties("${JWT_ISSUER}", AUDIENCE, "k-current", null, null, 1L, 1L)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_ISSUER");
    }

    /** An unset lifetime binds to 0, which would issue every token already expired. */
    @Test
    void refusesALifetimeThatIsNotPositive() {
        JwtSigningKeys keys = new JwtSigningKeys("k-current", JwtTestKeys.privatePem(CURRENT),
                JwtTestKeys.jwks(JwtTestKeys.publicJwk("k-current", CURRENT)), MAPPER);

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new JwtTokenProvider(keys,
                        new JwtProperties(ISSUER, AUDIENCE, "k-current", null, null, 0L, 1L)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_EXPIRATION");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new JwtTokenProvider(keys,
                        new JwtProperties(ISSUER, AUDIENCE, "k-current", null, null, 1L, 0L)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_REFRESH_EXPIRATION");
    }
}
