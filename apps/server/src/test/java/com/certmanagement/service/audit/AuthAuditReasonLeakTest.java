// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.dto.auth.SsoUserInfo;
import com.certmanagement.entity.Organization;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import com.certmanagement.security.oidc.SsoConfig;
import com.certmanagement.interceptor.RequestContextInterceptor;
import com.certmanagement.security.AuthenticationEventLogger;
import com.certmanagement.security.ClientAddressResolver;
import com.certmanagement.security.ClientIpSource;
import com.certmanagement.security.JwtAuthenticationEntryPoint;
import com.certmanagement.security.JwtTokenProvider;
import com.certmanagement.security.OidcAuthenticationFailureHandler;
import com.certmanagement.security.OidcAuthenticationSuccessHandler;
import com.certmanagement.service.RefreshTokenService;
import com.certmanagement.service.SsoAttributeExtractor;
import com.certmanagement.service.SsoAuthenticationService;
import com.certmanagement.service.UserProvisioningService;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Sign-in failures thrown with SQL, connection
 * strings, hostnames, token endpoint URLs, vault names and stack frames in their messages leave none of it
 * in the stored audit row, in the {@code AUTH_EVENT} log line, or in the redirect the browser follows. The
 * row and the line carry a reason code instead.
 */
class AuthAuditReasonLeakTest {

    private static final String LEAKY = "FATAL: password authentication failed for user \"certping_app\" "
            + "jdbc:postgresql://pg-example.postgres.database.azure.com:5432/certping "
            + "SELECT password_hash FROM users WHERE email='x' "
            + "vault example-vault-prod-weu secret sso-signing-key "
            + "POST https://oauth2.googleapis.com/token 10.20.30.40 "
            + "at com.certmanagement.service.SecretThing.load(SecretThing.java:42)";
    private static final List<String> FRAGMENTS = List.of("jdbc:postgresql", "pg-example", "database.azure.com",
            "SELECT password_hash", "example-vault", "sso-signing-key", "oauth2.googleapis.com", "10.20.30.40",
            "SecretThing", "certping_app");

    private static final ClientAddressResolver RESOLVER = new ClientAddressResolver(ClientIpSource.LAST_PROXY_HOP, null);

    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final AuthAuditRecorder authAudit = new AuthAuditRecorder(recorder, Clock.systemUTC());
    private final List<ListAppender<ILoggingEvent>> appenders = new ArrayList<>();

    @BeforeEach
    void capture() {
        for (Class<?> source : List.of(OidcAuthenticationSuccessHandler.class,
                OidcAuthenticationFailureHandler.class, AuthenticationEventLogger.class,
                JwtAuthenticationEntryPoint.class)) {
            ListAppender<ILoggingEvent> appender = new ListAppender<>();
            appender.start();
            ((Logger) LoggerFactory.getLogger(source)).addAppender(appender);
            appenders.add(appender);
        }
        RequestContextInterceptor.setCurrentClientIp("203.0.113.9");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
    }

    @AfterEach
    void release() {
        List<Class<?>> sources = List.of(OidcAuthenticationSuccessHandler.class,
                OidcAuthenticationFailureHandler.class, AuthenticationEventLogger.class,
                JwtAuthenticationEntryPoint.class);
        for (int i = 0; i < sources.size(); i++) {
            ((Logger) LoggerFactory.getLogger(sources.get(i))).detachAppender(appenders.get(i));
        }
        RequestContextInterceptor.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }



    @Test
    void anSsoSignInFailingWithADatabaseErrorStoresAndLogsOnlyACode() throws Exception {
        PlatformOidcRegistration configs = mock(PlatformOidcRegistration.class);
        SsoAttributeExtractor extractor = mock(SsoAttributeExtractor.class);
        UserProvisioningService provisioning = mock(UserProvisioningService.class);
        when(configs.owns("reg")).thenReturn(true);
        when(configs.ssoConfig()).thenReturn(Optional.of(SsoConfig.builder()
                .organization(Organization.builder().id(42L).name("Acme").build()).registrationId("reg")
                .build()));
        when(extractor.extractFromOAuth2(any(), any(), any())).thenReturn(SsoUserInfo.builder().email("a@acme.test")
                .build());
        when(provisioning.findOrProvisionUser(any(), any(), any()))
                .thenThrow(new DataAccessResourceFailureException(LEAKY));
        SsoAuthenticationService sso = new SsoAuthenticationService(extractor, provisioning,
                mock(JwtTokenProvider.class), configs, mock(RefreshTokenService.class),
                authAudit);
        OidcAuthenticationSuccessHandler handler = new OidcAuthenticationSuccessHandler(sso, RESOLVER,
                org.mockito.Mockito.mock(com.certmanagement.security.SsoLoginCodes.class));
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", "https://app.test/sso/callback");
        OAuth2AuthenticationToken token = mock(OAuth2AuthenticationToken.class);
        when(token.getAuthorizedClientRegistrationId()).thenReturn("reg");
        when(token.getPrincipal()).thenReturn(mock(org.springframework.security.oauth2.core.user.OAuth2User.class));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest("GET", "/login/oauth2/code/reg"), response, token);

        assertThat(authEventLines()).filteredOn(line -> line.contains("failure")).singleElement()
                .satisfies(line -> assertThat(line).contains("reason=INTERNAL_ERROR")
                        .contains("cause=DataAccessResourceFailureException"));
        assertClean(String.join("\n", authEventLines()));
        assertClean(response.getRedirectedUrl());
        AuditEventRow row = failed();
        assertThat(row.errorCode()).isEqualTo("INTERNAL_ERROR");
        assertClean(row.toString());
    }

    @Test
    void anOidcTokenRejectedWithTheIdpsTextLogsTheFrameworkCodeOnly() throws Exception {
        OidcAuthenticationFailureHandler handler = new OidcAuthenticationFailureHandler(authAudit, RESOLVER);
        ReflectionTestUtils.setField(handler, "frontendRedirectUrl", "https://app.test/sso/callback");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest("GET", "/login/oauth2/code/reg"), response,
                new OAuth2AuthenticationException(new OAuth2Error("invalid_id_token", LEAKY, null), LEAKY));

        assertThat(authEventLines()).singleElement().satisfies(line -> assertThat(line)
                .contains("reason=SSO_REJECTED").contains("providerError=invalid_id_token"));
        assertClean(String.join("\n", authEventLines()));
        assertClean(response.getRedirectedUrl());
        assertClean(failed().toString());
    }

    @Test
    void frameworkAndResourceAuthFailuresLogTheirTypeNotTheirText() throws Exception {
        new AuthenticationEventLogger(RESOLVER).onAuthenticationFailure(new AuthenticationFailureBadCredentialsEvent(
                new UsernamePasswordAuthenticationToken("x", "y"), new BadCredentialsException(LEAKY)));
        new JwtAuthenticationEntryPoint(JsonMapper.builderWithJackson2Defaults().build(), RESOLVER).commence(new MockHttpServletRequest("GET", "/api/v1/certs"),
                new MockHttpServletResponse(), new InsufficientAuthenticationException(LEAKY));

        assertThat(authEventLines()).hasSize(2);
        assertThat(authEventLines().get(0)).contains("reason=SSO_REJECTED").contains("cause=BadCredentialsException");
        assertThat(authEventLines().get(1)).contains("reason=missing_token");
        assertClean(String.join("\n", authEventLines()));
    }

    @Test
    void aPasswordRefusalNeverCarriesTheExceptionText() {
        assertThatThrownBy(() -> {
            throw new com.certmanagement.security.SignInRefusedException(
                    com.certmanagement.audit.AuditReason.of(LEAKY), null, LEAKY);
        }).satisfies(e -> {
            authAudit.signInFailed(e, null, AuthAuditRecorder.Method.PASSWORD, null);
            AuditEventRow row = failed();
            assertThat(row.errorCode()).as("free text can never be stored as a code").isEqualTo("INTERNAL_ERROR");
            assertClean(row.toString());
        });
    }

    private List<String> authEventLines() {
        List<String> lines = new ArrayList<>();
        appenders.forEach(appender -> appender.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(message -> message.contains("AUTH_EVENT")).forEach(lines::add));
        return lines;
    }

    private AuditEventRow failed() {
        ArgumentCaptor<AuditEventRow> row = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).recordFailure(row.capture());
        return row.getValue();
    }

    private static void assertClean(String text) {
        assertThat(text).isNotNull();
        for (String fragment : FRAGMENTS) {
            assertThat(text).as("must not contain %s", fragment).doesNotContain(fragment);
        }
    }
}
