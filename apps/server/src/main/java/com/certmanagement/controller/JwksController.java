// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.security.JwtSigningKeys;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/**
 * The public keys that verify CertPing access tokens. Other services cache this and refresh it on an
 * unknown kid, so keep the cache short enough that a newly published key reaches them before it signs.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Token verification keys")
public class JwksController {

    private final JwtSigningKeys keys;

    @GetMapping(value = Paths.JWKS, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(keys.publicJwksJson());
    }
}
