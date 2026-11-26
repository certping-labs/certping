// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.JwtSigningKeys;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwksControllerTest {

    @Test
    void servesThePublicKeySetWithAShortPublicCache() {
        JwtSigningKeys keys = mock(JwtSigningKeys.class);
        when(keys.publicJwksJson()).thenReturn("{\"keys\":[]}");

        ResponseEntity<String> response = new JwksController(keys).jwks();

        assertThat(response.getBody()).isEqualTo("{\"keys\":[]}");
        assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("max-age=300, public");
    }
}
