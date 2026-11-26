// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.JwtClaims;
import com.certmanagement.repository.ActivationStateProjection;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.UserAccessStateProjection;
import com.certmanagement.repository.UserRepository;
import com.certmanagement.service.AccessTokenBlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private UserRepository userRepository;
    @Mock private OrganizationRepository organizationRepository;
    @Mock private AccessTokenBlacklistService accessTokenBlacklistService;
    @Mock private FilterChain filterChain;

    @InjectMocks
    private JwtAuthenticationFilter filter;

    private static final String TOKEN = "valid.jwt.token";

    @AfterEach
    void cleanup() {
        SecurityContextHolder.clearContext();
        GatewayRequestContext.clear();
        MDC.clear();
    }

    private MockHttpServletRequest reqWithBearer() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/certificates");
        req.addHeader(JwtClaims.AUTHORIZATION, JwtClaims.BEARER_PREFIX + TOKEN);
        return req;
    }

    @Test
    void doFilter_noToken_passesThroughWithoutAuthentication() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/x");
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_invalidToken_doesNotAuthenticate() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.empty());
        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_validLocalToken_setsAuthenticationWithRolesAndPermissions() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("user@acme.com", 42, 1L, List.of("ORGANIZATION_ADMIN"), List.of("certificate:read"), JwtClaims.AUTH_METHOD_LOCAL)));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("user@acme.com");
        assertThat(auth.getAuthorities()).extracting("authority")
                .contains("ROLE_ORGANIZATION_ADMIN", "certificate:read");
        assertThat(req.getAttribute(JwtClaims.USER_ID)).isEqualTo(42);
        verify(filterChain).doFilter(req, resp);
        verify(userRepository).findAccessStateById(42);
        // Locks in the point of the change: the full entity graph must not be loaded per request.
        verify(userRepository, never()).findById(any());
        verify(organizationRepository, never()).findById(any());
    }

    @Test
    void doFilter_ssoToken_activeUser_authenticates() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("sso@acme.com", 42, 1L, List.of("VIEWER"), List.of(), "SSO")));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(req, resp);
    }

    @Test
    void doFilter_ssoToken_inactiveUser_rejectsWith401() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("sso@acme.com", 42, 1L, List.of(), List.of(), "SSO")));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(false, false)));

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(resp.getContentAsString()).contains("disabled or deleted");
        verify(filterChain, never()).doFilter(any(), any());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_ssoToken_userNotFound_rejects() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("sso@acme.com", 42, 1L, List.of(), List.of(), "SSO")));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.empty());

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilter_ssoToken_inactiveOrg_rejects() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("sso@acme.com", 42, 1L, List.of(), List.of(), "SSO")));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(false, false)));

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(resp.getContentAsString()).contains("suspended or inactive");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilter_exceptionDuringValidation_isSwallowedAndChainProceeds() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenThrow(new RuntimeException("kaboom"));
        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    // ---------- shouldNotFilter ----------

    @Test
    void doFilter_mintsADifferentRequestIdForEveryRequest() throws Exception {
        authenticatesUser42();
        List<String> minted = new ArrayList<>();
        doAnswer(invocation -> minted.add(GatewayRequestContext.getRequestId())).when(filterChain).doFilter(any(), any());

        filter.doFilter(reqWithBearer(), new MockHttpServletResponse(), filterChain);
        filter.doFilter(reqWithBearer(), new MockHttpServletResponse(), filterChain);

        assertThat(minted).hasSize(2).doesNotHaveDuplicates()
                .allSatisfy(id -> assertThat(id).matches("req-[0-9a-f-]{36}"));
    }

    @Test
    void doFilter_removesItsMdcKeysAfterTheChain() throws Exception {
        authenticatesUser42();
        MockHttpServletRequest req = reqWithBearer();
        req.addHeader("X-Correlation-ID", "corr-1");
        Map<String, String> duringChain = new HashMap<>();
        doAnswer(invocation -> {
            duringChain.putAll(MDC.getCopyOfContextMap());
            return null;
        }).when(filterChain).doFilter(any(), any());

        filter.doFilter(req, new MockHttpServletResponse(), filterChain);

        assertThat(duringChain).containsKeys("requestId", "correlationId", "organizationId");
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void doFilter_removesItsMdcKeysWhenTheChainThrows() throws Exception {
        authenticatesUser42();
        MockHttpServletRequest req = reqWithBearer();
        req.addHeader("X-Correlation-ID", "corr-1");
        doThrow(new ServletException("rejected downstream")).when(filterChain).doFilter(any(), any());

        assertThatThrownBy(() -> filter.doFilter(req, new MockHttpServletResponse(), filterChain))
                .isInstanceOf(ServletException.class);

        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    private void authenticatesUser42() {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("user@acme.com", 42, 1L, List.of("VIEWER"), List.of(), JwtClaims.AUTH_METHOD_LOCAL)));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));
    }

    @Test
    void shouldNotFilter_optionsRequest_true() {
        MockHttpServletRequest req = new MockHttpServletRequest("OPTIONS", "/api/x");
        assertThat(filter.shouldNotFilter(req)).isTrue();
    }

    @Test
    void shouldNotFilter_changePassword_false() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/change-password");
        assertThat(filter.shouldNotFilter(req)).isFalse();
    }

    @Test
    void shouldNotFilter_accountMfaEndpoints_false_butSecondSignInStep_true() {
        for (String path : List.of("/api/auth/mfa", "/api/auth/mfa/enroll", "/api/auth/mfa/confirm")) {
            assertThat(filter.shouldNotFilter(new MockHttpServletRequest("POST", path))).as(path).isFalse();
        }
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("POST", "/api/auth/login/mfa"))).isTrue();
    }

    @Test
    void shouldNotFilter_anonymousAuthPath_true() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/auth/login");
        assertThat(filter.shouldNotFilter(req)).isTrue();
    }

    @Test
    void shouldNotFilter_jwksPath_true() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/.well-known/jwks.json");
        assertThat(filter.shouldNotFilter(req)).isTrue();
    }

    @Test
    void shouldNotFilter_publicStatus_true() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/public/status");
        req.addHeader("Authorization", "Bearer stray-token");
        assertThat(filter.shouldNotFilter(req)).isTrue();
    }

    @Test
    void shouldNotFilter_pathsBesidePublicStatus_false() {
        for (String path : new String[] {"/api/v1/public/status/x", "/api/v1/public/statuses", "/api/v1/public/contact"}) {
            assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", path))).as(path).isFalse();
        }
    }

    @Test
    void shouldNotFilter_protectedApiPath_false() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/certificates");
        assertThat(filter.shouldNotFilter(req)).isFalse();
    }

    /**
     * Pins existing behaviour, which the projection must not alter: an absent organization does not
     * reject. Note the asymmetry it produces with {@code @Where} — a soft-deleted user is rejected
     * because absence fails the user check, while a soft-deleted organization is admitted because
     * absence skips the organization check. Whether that asymmetry is wanted is a separate question.
     */
    @Test
    void doFilter_ssoToken_orgNotFound_authenticates() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("sso@acme.com", 42, 1L, List.of(), List.of(), "SSO")));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.empty());

        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verify(filterChain).doFilter(req, resp);
    }

    private static AccessToken accessToken(String email, int userId, long orgId, List<String> roles,
                                           List<String> permissions, String authMethod) {
        return new AccessToken("jti-1", email, userId, orgId, roles, permissions, authMethod,
                java.time.Instant.now().plusSeconds(600));
    }

    private static UserAccessStateProjection userState(boolean active, boolean deleted) {
        return userState(active, deleted, false, null);
    }

    private static UserAccessStateProjection userState(boolean active, boolean deleted, boolean mustChangePassword,
                                                       java.time.OffsetDateTime tokensValidAfter) {
        return new UserAccessStateProjection() {
            @Override
            public Boolean getActive() {
                return active;
            }

            @Override
            public Boolean getIsDeleted() {
                return deleted;
            }

            @Override
            public Boolean getMustChangePassword() {
                return mustChangePassword;
            }

            @Override
            public java.time.OffsetDateTime getTokensValidAfter() {
                return tokensValidAfter;
            }
        };
    }

    // ---------- tokens_valid_after (role, permission or password changes) ----------

    private static AccessToken issuedAt(java.time.Instant iat) {
        return new AccessToken("jti-old", "user@acme.com", 42, 1L, List.of("ORGANIZATION_ADMIN"), List.of(),
                JwtClaims.AUTH_METHOD_LOCAL, java.time.Instant.now().plusSeconds(600), iat);
    }

    @Test
    void doFilter_tokenIssuedBeforeTheUsersRevocation_isRefusedWith401() throws Exception {
        java.time.OffsetDateTime revokedAt = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC)
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        when(jwtTokenProvider.parseAccessToken(TOKEN))
                .thenReturn(Optional.of(issuedAt(revokedAt.toInstant().minusSeconds(60))));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false, false, revokedAt)));
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(reqWithBearer(), resp, filterChain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        verify(filterChain, never()).doFilter(any(), any());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void doFilter_tokenIssuedAtOrAfterTheRevocation_authenticates() throws Exception {
        java.time.OffsetDateTime revokedAt = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC)
                .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(issuedAt(revokedAt.toInstant())));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false, false, revokedAt)));
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));
        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        assertThat(req.getAttribute(JwtAuthenticationFilter.ACCESS_TOKEN_ATTRIBUTE)).isNotNull();
    }

    @Test
    void doFilter_theTokenThatChangedThePassword_staysValid() throws Exception {
        java.time.OffsetDateTime revokedAt = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC);
        when(jwtTokenProvider.parseAccessToken(TOKEN))
                .thenReturn(Optional.of(issuedAt(revokedAt.toInstant().minusSeconds(60))));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false, false, revokedAt)));
        when(accessTokenBlacklistService.isExempt("jti-old")).thenReturn(true);
        when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));
        MockHttpServletRequest req = reqWithBearer();
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
    }

    // ---------- mustChangePassword ----------

    @Test
    void doFilter_userWhoMustChangeThePassword_isRefusedEverywhereElse() throws Exception {
        when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                accessToken("user@acme.com", 42, 1L, List.of("SUPER_ADMIN"), List.of(), JwtClaims.AUTH_METHOD_LOCAL)));
        when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false, true, null)));
        MockHttpServletResponse resp = new MockHttpServletResponse();

        filter.doFilter(reqWithBearer(), resp, filterChain);

        assertThat(resp.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(resp.getContentAsString()).contains("\"code\":\"PASSWORD_CHANGE_REQUIRED\"");
        verify(filterChain, never()).doFilter(any(), any());
    }

    @Test
    void doFilter_userWhoMustChangeThePassword_mayChangeItAndReadDeploymentInfo() throws Exception {
        for (String path : List.of("/api/auth/change-password", "/api/v1/admin/change-password",
                "/api/v1/deployment-info", "/api/auth/me", "/api/auth/logout", "/api/auth/refresh")) {
            org.mockito.Mockito.reset(filterChain);
            when(jwtTokenProvider.parseAccessToken(TOKEN)).thenReturn(Optional.of(
                    accessToken("user@acme.com", 42, 1L, List.of(), List.of(), JwtClaims.AUTH_METHOD_LOCAL)));
            when(userRepository.findAccessStateById(42)).thenReturn(Optional.of(userState(true, false, true, null)));
            when(organizationRepository.findActivationStateById(1L)).thenReturn(Optional.of(activation(true, false)));
            MockHttpServletRequest req = new MockHttpServletRequest("POST", path);
            req.addHeader(JwtClaims.AUTHORIZATION, JwtClaims.BEARER_PREFIX + TOKEN);
            MockHttpServletResponse resp = new MockHttpServletResponse();

            filter.doFilterInternal(req, resp, filterChain);

            assertThat(resp.getStatus()).as(path).isEqualTo(200);
            verify(filterChain).doFilter(req, resp);
        }
    }

    private static ActivationStateProjection activation(boolean active, boolean deleted) {
        return new ActivationStateProjection() {
            @Override
            public Boolean getActive() {
                return active;
            }

            @Override
            public Boolean getIsDeleted() {
                return deleted;
            }
        };
    }
}
