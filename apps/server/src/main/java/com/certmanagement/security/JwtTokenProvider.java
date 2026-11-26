// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.ProtectedHeader;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Issues and verifies access and refresh tokens. Tokens are RS256 with a {@code kid}, an issuer, an
 * audience and a type, so other services can verify them from the published JWKS without holding
 * anything that could mint one.
 */
@Component
@Slf4j
public class JwtTokenProvider {

    /** How long after {@code exp} a token is still accepted, for clock drift between services. */
    public static final Duration CLOCK_SKEW = Duration.ofSeconds(30);

    private final JwtSigningKeys keys;
    private final JwtProperties properties;
    private final JwtParser parser;

    public JwtTokenProvider(JwtSigningKeys keys, JwtProperties properties) {
        requireText(properties.issuer(), "jwt.issuer (JWT_ISSUER)");
        requireText(properties.audience(), "jwt.audience (JWT_AUDIENCE)");
        requirePositive(properties.expiration(), "jwt.expiration (JWT_EXPIRATION)");
        requirePositive(properties.refreshExpiration(), "jwt.refresh-expiration (JWT_REFRESH_EXPIRATION)");
        this.keys = keys;
        this.properties = properties;
        this.parser = Jwts.parser()
                .keyLocator(new PublishedKeyLocator(keys))
                .requireIssuer(properties.issuer())
                .requireAudience(properties.audience())
                .clockSkewSeconds(CLOCK_SKEW.toSeconds())
                .build();
    }

    /** {@code organization} is null for the bootstrap admin, who has no organization yet. */
    public String generateAccessToken(User user, @Nullable Organization organization, String authMethod) {
        Date now = new Date();
        return Jwts.builder()
                .header().keyId(keys.signingKeyId()).and()
                .id(UUID.randomUUID().toString())
                .issuer(properties.issuer())
                .audience().add(properties.audience()).and()
                .subject(user.getEmail())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + properties.expiration()))
                .claim(JwtClaims.TOKEN_TYPE, JwtClaims.TOKEN_TYPE_ACCESS)
                .claim(JwtClaims.USER_ID, user.getId())
                .claim(JwtClaims.ORGANIZATION_ID, organizationId(organization))
                .claim(JwtClaims.ORGANIZATION_NAME, organization != null ? organization.getName() : null)
                // Kept for the agent and web contract: every organization is B2B; null for SUPER_ADMIN.
                .claim(JwtClaims.ORG_TYPE, organization != null ? organization.getOrgType() : null)
                .claim(JwtClaims.ROLES, new ArrayList<>(user.getRoleNames()))
                .claim(JwtClaims.PERMISSIONS, permissionsClaim(user, organization))
                .claim(JwtClaims.AUTH_METHOD, authMethod)
                .signWith(keys.signingKey(), Jwts.SIG.RS256)
                .compact();
    }

    /** Each refresh token has its own {@code jti} so it can be revoked on its own. */
    public String generateRefreshToken(User user, @Nullable Organization organization) {
        Date now = new Date();
        return Jwts.builder()
                .header().keyId(keys.signingKeyId()).and()
                .id(UUID.randomUUID().toString())
                .issuer(properties.issuer())
                .audience().add(properties.audience()).and()
                .subject(user.getEmail())
                .issuedAt(now)
                .expiration(new Date(now.getTime() + properties.refreshExpiration()))
                .claim(JwtClaims.TOKEN_TYPE, JwtClaims.TOKEN_TYPE_REFRESH)
                .claim(JwtClaims.USER_ID, user.getId())
                .claim(JwtClaims.ORGANIZATION_ID, organizationId(organization))
                .signWith(keys.signingKey(), Jwts.SIG.RS256)
                .compact();
    }

    /** Empty unless the token verifies and is an access token. Never throws. */
    public Optional<AccessToken> parseAccessToken(@Nullable String token) {
        return verified(token, JwtClaims.TOKEN_TYPE_ACCESS).map(claims -> new AccessToken(
                claims.getId(),
                claims.getSubject(),
                claims.get(JwtClaims.USER_ID, Integer.class),
                readOrganizationId(claims),
                stringList(claims, JwtClaims.ROLES),
                stringList(claims, JwtClaims.PERMISSIONS),
                claims.get(JwtClaims.AUTH_METHOD, String.class),
                claims.getExpiration().toInstant(),
                claims.getIssuedAt() != null ? claims.getIssuedAt().toInstant() : null));
    }

    /** Empty unless the token verifies and is a refresh token. Never throws. */
    public Optional<RefreshToken> parseRefreshToken(@Nullable String token) {
        return verified(token, JwtClaims.TOKEN_TYPE_REFRESH).map(claims -> new RefreshToken(
                claims.getId(),
                claims.getSubject(),
                claims.get(JwtClaims.USER_ID, Integer.class),
                readOrganizationId(claims),
                claims.getExpiration().toInstant()));
    }

    public long getExpirationTime() {
        return properties.expiration();
    }

    private Optional<Claims> verified(@Nullable String token, String expectedType) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            Claims claims = parser.parseSignedClaims(token).getPayload();
            if (!expectedType.equals(claims.get(JwtClaims.TOKEN_TYPE, String.class)) || claims.getExpiration() == null) {
                log.debug("JWT rejected: expected a {} token", expectedType);
                return Optional.empty();
            }
            return Optional.of(claims);
        } catch (ExpiredJwtException e) {
            log.debug("JWT rejected: expired");
        } catch (JwtException | IllegalArgumentException e) {
            // Class name only: token contents and parser messages stay out of the logs.
            log.debug("JWT rejected: {}", e.getClass().getSimpleName());
        }
        return Optional.empty();
    }

    private List<String> permissionsClaim(User user, @Nullable Organization organization) {
        return new ArrayList<>(effectivePermissions(user, organization));
    }

    /** The permissions a token issued now would carry: role and direct grants. */
    public Set<String> effectivePermissions(User user, @Nullable Organization organization) {
        return new LinkedHashSet<>(user.getEffectivePermissionNames());
    }

    @Nullable
    private static String organizationId(@Nullable Organization organization) {
        return organization != null && organization.getId() != null ? organization.getId().toString() : null;
    }

    @Nullable
    private static Long readOrganizationId(Claims claims) {
        Object value = claims.get(JwtClaims.ORGANIZATION_ID);
        if (value instanceof Number number) {
            return number.longValue();
        }
        return value == null ? null : Long.parseLong(String.valueOf(value));
    }

    private static List<String> stringList(Claims claims, String name) {
        Object value = claims.get(name);
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        return list.stream().map(String::valueOf).toList();
    }

    private static void requireText(@Nullable String value, String setting) {
        // The binder keeps an unresolved placeholder as literal text, so "${JWT_ISSUER}" means unset.
        if (value == null || value.isBlank() || value.contains("${")) {
            throw new IllegalStateException(setting + " is required");
        }
    }

    private static void requirePositive(long millis, String setting) {
        if (millis <= 0) {
            throw new IllegalStateException(setting + " must be a positive number of milliseconds");
        }
    }

    /**
     * The server decides the algorithm, never the token. Refusing anything but RS256 here blocks
     * {@code alg: none} and HS256 keyed with the public key, which anyone can read from the JWKS.
     * The kid only selects which published key to try; the signature is what proves the token.
     */
    private static final class PublishedKeyLocator extends LocatorAdapter<Key> {
        private final JwtSigningKeys keys;

        PublishedKeyLocator(JwtSigningKeys keys) {
            this.keys = keys;
        }

        @Override
        protected Key locate(ProtectedHeader header) {
            if (!JwtSigningKeys.ALGORITHM.equals(header.getAlgorithm())) {
                throw new SecurityException("JWT algorithm not allowed: " + header.getAlgorithm());
            }
            return keys.publishedKey(header.getKeyId())
                    .orElseThrow(() -> new SecurityException("JWT kid is not published"));
        }

        @Override
        protected Key doLocate(Header header) {
            throw new SecurityException("Unsigned JWTs are not accepted");
        }
    }
}
