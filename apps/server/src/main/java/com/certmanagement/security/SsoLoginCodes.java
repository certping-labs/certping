// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.dto.auth.AuthTokenResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * One-time codes that carry a single sign-on result from the IdP callback to the web app. The callback
 * redirects with {@code ?code=} instead of the tokens, so the tokens never sit in a URL (browser history,
 * proxy and access logs, {@code Referer}); the web app trades the code once for the tokens with
 * {@code POST /api/auth/sso/exchange}. A code is 32 random bytes, lives {@value #TTL_SECONDS} seconds in
 * Redis and is consumed by an atomic GETDEL, so it works at most once.
 */
@Slf4j
@Component
public class SsoLoginCodes {

    static final String KEY_PREFIX = "auth:sso-code:";
    static final long TTL_SECONDS = 60;
    /** 32 bytes, base64url without padding. */
    private static final Pattern CODE = Pattern.compile("[A-Za-z0-9_-]{43}");

    private final StringRedisTemplate redis;
    private final ObjectMapper objectMapper;
    private final SecureRandom random = new SecureRandom();

    public SsoLoginCodes(StringRedisTemplate redis, ObjectMapper objectMapper) {
        this.redis = redis;
        this.objectMapper = objectMapper;
    }

    /** Stores the sign-in result and returns the code that redeems it. Throws when Redis is unavailable. */
    public String issue(AuthTokenResponse result) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redis.opsForValue().set(KEY_PREFIX + code, objectMapper.writeValueAsString(result),
                Duration.ofSeconds(TTL_SECONDS));
        return code;
    }

    /** The sign-in result the code was issued for, removing it; empty for an unknown, used or expired code. */
    public Optional<AuthTokenResponse> redeem(String code) {
        if (code == null || !CODE.matcher(code).matches()) {
            return Optional.empty();
        }
        String json = redis.opsForValue().getAndDelete(KEY_PREFIX + code);
        if (json == null) {
            return Optional.empty();
        }
        return Optional.of(objectMapper.readValue(json, AuthTokenResponse.class));
    }
}
