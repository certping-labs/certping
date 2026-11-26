// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.dto.auth.AuthTokenResponse;
import com.certmanagement.dto.auth.LocalLoginResponse;
import com.certmanagement.dto.auth.UnifiedLoginRequest;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.User;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.UnauthorizedException;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.security.AccessToken;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.RefreshToken;
import com.certmanagement.service.AccessTokenBlacklistService;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.UnifiedAuthService;
import com.certmanagement.service.audit.AuthAuditRecorder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerMoreTest {

    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private UserRepository userRepository;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private AccessTokenBlacklistService accessTokenBlacklistService;
    @Mock private UnifiedAuthService unifiedAuthService;

    private AuthController controller;

    private static final String RT = "refresh-token";

    @BeforeEach
    void setUp() {
        controller = new AuthController(jwtTokenProvider, userRepository, refreshTokenService, accessTokenBlacklistService, unifiedAuthService, mock(AuthAuditRecorder.class));
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private User activeUser(Organization org) {
        return User.builder()
                .id(101).email("user@example.com").organization(org).active(true)
                .build();
    }

    // ── login ─────────────────────────────────────────────────────────

    @Test
    void login_delegatesToService() {
        UnifiedLoginRequest req = new UnifiedLoginRequest();
        LocalLoginResponse resp = LocalLoginResponse.builder().token("tok").build();
        when(unifiedAuthService.login(req)).thenReturn(resp);

        assertThat(controller.login(req).getBody()).isEqualTo(resp);
    }

    // ── refreshToken ──────────────────────────────────────────────────

    private static RefreshToken parsedRefresh(Integer userId, Long orgId) {
        return new RefreshToken("jti-rt", "user@example.com", userId, orgId, Instant.now().plusSeconds(3600));
    }

    private static final AccessToken ACCESS = new AccessToken("jti-at", "user@example.com", 101, 10L,
            List.of("ADMIN"), List.of("CERTIFICATE_READ"), "LOCAL", Instant.now().plusSeconds(600));

    @Test
    void refreshToken_notAVerifiedRefreshToken_throwsBadRequest() {
        when(jwtTokenProvider.parseRefreshToken(RT)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> controller.refreshToken(Map.of("refreshToken", RT)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    @Test
    void refreshToken_blacklisted_throwsUnauthorized() {
        RefreshToken parsed = parsedRefresh(101, 10L);
        when(jwtTokenProvider.parseRefreshToken(RT)).thenReturn(Optional.of(parsed));
        when(refreshTokenService.isBlacklisted(parsed)).thenReturn(true);

        assertThatThrownBy(() -> controller.refreshToken(Map.of("refreshToken", RT)))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void refreshToken_inactiveUser_throwsUnauthorized() {
        Organization org = Organization.builder().id(10L).name("Acme").active(true).isDeleted(false).build();
        User user = User.builder().id(101).email("user@example.com").organization(org).active(false).build();
        stubValidRefresh(101, 10L);
        when(userRepository.findById(101)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> controller.refreshToken(Map.of("refreshToken", RT)))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("not authorized");
    }

    @Test
    void refreshToken_suspendedOrganization_throwsUnauthorized() {
        Organization org = Organization.builder().id(10L).name("Acme").active(false).isDeleted(false).build();
        User user = activeUser(org);
        stubValidRefresh(101, 10L);
        when(userRepository.findById(101)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> controller.refreshToken(Map.of("refreshToken", RT)))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("suspended");
    }

    @Test
    void refreshToken_orgMismatch_throwsUnauthorized() {
        Organization org = Organization.builder().id(99L).name("Acme").active(true).isDeleted(false).build();
        User user = activeUser(org);
        stubValidRefresh(101, 10L); // token says org 10, user is in org 99
        when(userRepository.findById(101)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> controller.refreshToken(Map.of("refreshToken", RT)))
                .isInstanceOf(UnauthorizedException.class)
                .hasMessageContaining("organization does not match");
    }

    @Test
    void refreshToken_happyPath_rotatesAndReturnsTokens() {
        Organization org = Organization.builder().id(10L).name("Acme").active(true).isDeleted(false).build();
        User user = User.builder()
                .id(101).email("user@example.com").organization(org).active(true)
                .authMethod(User.AuthMethod.LOCAL)
                .build();
        RefreshToken parsed = stubValidRefresh(101, 10L);
        when(userRepository.findById(101)).thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateAccessToken(eq(user), eq(org), any())).thenReturn("new-access");
        when(jwtTokenProvider.generateRefreshToken(user, org)).thenReturn("new-refresh");
        when(jwtTokenProvider.getExpirationTime()).thenReturn(3600L);
        when(refreshTokenService.getRecordedAuthMethod(parsed)).thenReturn("SOCIAL");

        ResponseEntity<AuthTokenResponse> resp = controller.refreshToken(Map.of("refreshToken", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody().getAccessToken()).isEqualTo("new-access");
        assertThat(resp.getBody().getRefreshToken()).isEqualTo("new-refresh");
        verify(refreshTokenService).recordIssued("new-refresh", user, "SOCIAL");
        verify(refreshTokenService).blacklist(parsed);
    }

    @Test
    void refreshToken_userViaEmailFallback_whenTokenHasNoUserId() {
        Organization org = Organization.builder().id(10L).name("Acme").active(true).isDeleted(false).build();
        User user = activeUser(org);
        RefreshToken parsed = stubValidRefresh(null, 10L);
        when(userRepository.findByEmailAndOrganizationId("user@example.com", 10L))
                .thenReturn(Optional.of(user));
        when(jwtTokenProvider.generateAccessToken(any(), any(), any())).thenReturn("a");
        when(jwtTokenProvider.generateRefreshToken(any(), any())).thenReturn("r");
        when(jwtTokenProvider.getExpirationTime()).thenReturn(3600L);
        when(refreshTokenService.getRecordedAuthMethod(parsed)).thenReturn(null); // fall back to authMethod

        ResponseEntity<AuthTokenResponse> resp = controller.refreshToken(Map.of("refreshToken", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(refreshTokenService).recordIssued(eq("r"), eq(user), any());
    }

    private RefreshToken stubValidRefresh(Integer userId, Long tokenOrgId) {
        RefreshToken parsed = parsedRefresh(userId, tokenOrgId);
        when(jwtTokenProvider.parseRefreshToken(RT)).thenReturn(Optional.of(parsed));
        when(refreshTokenService.isBlacklisted(parsed)).thenReturn(false);
        return parsed;
    }

    // ── validateToken ─────────────────────────────────────────────────

    @Test
    void validateToken_valid_returnsClaims() {
        when(jwtTokenProvider.parseAccessToken("tok")).thenReturn(Optional.of(ACCESS));

        ResponseEntity<Map<String, Object>> resp = controller.validateToken(Map.of("token", "tok"));

        assertThat(resp.getBody()).containsEntry("valid", true);
        assertThat(resp.getBody()).containsEntry("email", "user@example.com");
        assertThat(resp.getBody()).containsEntry("organizationId", 10L);
    }

    @Test
    void validateToken_revoked_returnsOnlyValidFalse() {
        when(jwtTokenProvider.parseAccessToken("tok")).thenReturn(Optional.of(ACCESS));
        when(accessTokenBlacklistService.isRevoked("jti-at")).thenReturn(true);

        ResponseEntity<Map<String, Object>> resp = controller.validateToken(Map.of("token", "tok"));

        assertThat(resp.getBody()).containsEntry("valid", false);
        assertThat(resp.getBody()).doesNotContainKey("email");
    }

    @Test
    void validateToken_invalid_returnsOnlyValidFalse() {
        when(jwtTokenProvider.parseAccessToken("bad")).thenReturn(Optional.empty());

        ResponseEntity<Map<String, Object>> resp = controller.validateToken(Map.of("token", "bad"));

        assertThat(resp.getBody()).containsEntry("valid", false);
        assertThat(resp.getBody()).doesNotContainKey("email");
    }

    // ── getCurrentUser ────────────────────────────────────────────────

    @Test
    void getCurrentUser_validToken_returnsUserInfo() {
        when(jwtTokenProvider.parseAccessToken("tok")).thenReturn(Optional.of(ACCESS));

        ResponseEntity<Map<String, Object>> resp = controller.getCurrentUser("Bearer tok");

        assertThat(resp.getBody()).containsEntry("email", "user@example.com");
        assertThat(resp.getBody()).containsEntry("userId", 101);
    }

    @Test
    void getCurrentUser_nullHeader_throwsBadRequest() {
        assertThatThrownBy(() -> controller.getCurrentUser(null))
                .isInstanceOf(BadRequestException.class);
    }

    // ── logout ────────────────────────────────────────────────────────

    @Test
    void logout_withValidRefreshToken_blacklistsBoth() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer access-tok");
        RefreshToken parsed = parsedRefresh(101, 10L);
        when(jwtTokenProvider.parseAccessToken("access-tok")).thenReturn(Optional.of(ACCESS));
        when(jwtTokenProvider.parseRefreshToken(RT)).thenReturn(Optional.of(parsed));

        ResponseEntity<Map<String, String>> resp = controller.logout(request, Map.of("refreshToken", RT));

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).containsEntry("message", "Logged out successfully");
        verify(accessTokenBlacklistService).revoke(ACCESS);
        verify(refreshTokenService).blacklist(parsed);
    }

    @Test
    void logout_nullBody_revokesAccessTokenOnly() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer access-tok");
        when(jwtTokenProvider.parseAccessToken("access-tok")).thenReturn(Optional.of(ACCESS));
        GatewayRequestContext.set(101, "10", "req-1", "user@example.com");

        ResponseEntity<Map<String, String>> resp = controller.logout(request, null);

        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        verify(accessTokenBlacklistService).revoke(ACCESS);
        verify(refreshTokenService, never()).blacklist(any());
    }
}
