// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.entity.Organization;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.service.RefreshTokenService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenService refreshTokenService;

    @InjectMocks
    private AuthController authController;

    @Test
    void refreshToken_missingToken_throwsBadRequest() {
        Map<String, String> request = new HashMap<>();

        assertThatThrownBy(() -> authController.refreshToken(request))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    @Test
    void refreshToken_userMismatch_throwsUnauthorized() {
        Map<String, String> request = Map.of("refreshToken", "refresh-token");
        Organization organization = Organization.builder().id(10L).name("Acme").build();

        when(jwtTokenProvider.parseRefreshToken("refresh-token")).thenReturn(Optional.of(new com.certmanagement.security.RefreshToken(
                "jti-1", "user@example.com", 101, 10L, java.time.Instant.now().plusSeconds(3600))));
        when(userRepository.findById(101)).thenReturn(Optional.of(
                com.certmanagement.entity.User.builder()
                        .id(101)
                        .email("different@example.com")
                        .organization(organization)
                        .active(true)
                        .build()));

        assertThatThrownBy(() -> authController.refreshToken(request))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Refresh token does not match user identity");
    }

    @Test
    void getCurrentUser_missingBearerPrefix_throwsBadRequest() {
        assertThatThrownBy(() -> authController.getCurrentUser("Token abc"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Bearer token");
    }

    @Test
    void getCurrentUser_invalidToken_throwsUnauthorized() {
        when(jwtTokenProvider.parseAccessToken("bad-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authController.getCurrentUser("Bearer bad-token"))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("Invalid or expired access token");
    }
}
