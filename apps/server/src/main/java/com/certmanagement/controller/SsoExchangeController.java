// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.security.SsoLoginCodes;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Trades the one-time code a single sign-on callback redirected with ({@code ?code=}) for the session's
 * tokens. Anonymous (under {@code /api/auth/**}) and rate limited per client address like the sign-in.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "SSO authentication and token management")
public class SsoExchangeController {

    public static final String PATH = "/api/auth/sso/exchange";

    private static final TypeReference<LinkedHashMap<String, Object>> MAP = new TypeReference<>() { };

    private final SsoLoginCodes ssoLoginCodes;
    private final ObjectMapper objectMapper;

    public record ExchangeRequest(String code) {
    }

    @PostMapping(PATH)
    @Operation(summary = "Exchange a single sign-on code for tokens",
            description = "Body {\"code\": \"...\"}. A code works once and for 60 seconds. Answers the sign-in "
                    + "response: accessToken (also as token), refreshToken, tokenType, expiresIn and the user fields.")
    public ResponseEntity<Map<String, Object>> exchange(@RequestBody(required = false) ExchangeRequest request) {
        AuthTokenResponse result = ssoLoginCodes.redeem(request == null ? null : request.code())
                .orElseThrow(() -> new BadRequestException("The sign-in code is invalid or has expired. Sign in again."));
        Map<String, Object> body = objectMapper.convertValue(result, MAP);
        // The password sign-in names the access token "token"; both names, so either client shape reads it.
        body.put("token", result.getAccessToken());
        return ResponseEntity.ok(body);
    }
}
