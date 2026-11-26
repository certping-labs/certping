// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.config;

import com.certmanagement.security.JwtAuthenticationEntryPoint;
import com.certmanagement.security.JwtAuthenticationFilter;
import com.certmanagement.security.OidcAuthenticationFailureHandler;
import com.certmanagement.security.OidcAuthenticationSuccessHandler;
import com.certmanagement.security.PasswordPepperProperties;
import com.certmanagement.security.PepperedPasswordEncoder;
import com.certmanagement.security.oidc.PlatformOidcProperties;
import com.certmanagement.security.oidc.PlatformOidcRegistration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.certmanagement.constants.Paths;
import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.List;

@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final OidcAuthenticationSuccessHandler oidcAuthenticationSuccessHandler;
    private final OidcAuthenticationFailureHandler oidcAuthenticationFailureHandler;
    private final PlatformOidcRegistration platformOidcRegistration;

    @Value("${cors.allowed-origins}")
    private String allowedOrigins;

    @Value("${cors.allowed-methods}")
    private String allowedMethods;

    @Value("${cors.allowed-headers}")
    private String allowedHeaders;

    @Value("${cors.expose-headers}")
    private String exposeHeaders;

    @Value("${cors.allow-credentials}")
    private boolean allowCredentials;

    @Value("${cors.max-age}")
    private long maxAge;

    /**
     * Security filter chain for the OIDC sign-in of the environment-configured provider (CERTPING_OIDC_*,
     * registration id "sso"). Without it, {@code /oauth2/**} does not exist.
     */
    @Bean
    @Order(1)
    @Conditional(PlatformOidcProperties.Configured.class)
    public SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/oauth2/**", "/login/oauth2/**")
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .oauth2Login(oauth2 -> oauth2
                .clientRegistrationRepository(registrationId -> platformOidcRegistration.owns(registrationId)
                        ? platformOidcRegistration.clientRegistration() : null)
                .successHandler(oidcAuthenticationSuccessHandler)
                .failureHandler(oidcAuthenticationFailureHandler)
            );

        return http.build();
    }

    /**
     * Main security filter chain for API endpoints
     */
    @Bean
    @Order(2)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(jwtAuthenticationEntryPoint))
            .authorizeHttpRequests(auth -> auth
                // Spring Security 6 authorizes every dispatch, not only the request's own. An ASYNC dispatch
                // (the re-dispatch after a StreamingResponseBody, e.g. an audit export, has written its body) and
                // an ERROR dispatch belong to a request this chain already authorized on its REQUEST dispatch,
                // where method security ran too; the JWT filter, a OncePerRequestFilter, does not run again on
                // them, so authorizing them again would find no authentication and deny a response that is
                // already committed (the client sees the stream reset). Spring Security's documented setting.
                .dispatcherTypeMatchers(DispatcherType.ASYNC, DispatcherType.ERROR).permitAll()
                // Allow preflight OPTIONS requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Public endpoints
                .requestMatchers(
                    // Sign-in, setup, password reset and refresh. The account's own endpoints under here
                    // (change-password, mfa) still pass the JWT filter and check identity themselves.
                    "/api/auth/**",
                    // The public status endpoint (Paths.PUBLIC_STATUS).
                    "/api/v1/public/**",
                    // Agent gateway: authenticated by agent bearer tokens inside the controller.
                    "/api/v1/agent-gateway/**",
                    "/actuator/health",
                    // Probe groups for kubelet; component detail under here is gated by show-details.
                    "/actuator/health/**",
                    "/actuator/info",
                    "/swagger-ui/**",
                    // API docs: off unless SWAGGER_ENABLED (selfhosted) or a dev/qa profile turns them on.
                    "/v3/api-docs/**",
                    "/swagger-ui.html/**"
                ).permitAll()
                // Public deployment metadata, read pre-auth by the frontend (first-run setup, sign-in options).
                .requestMatchers(HttpMethod.GET, Paths.DEPLOYMENT_INFO).permitAll()
                // Public keys that verify access tokens; other services fetch them unauthenticated.
                .requestMatchers(HttpMethod.GET, Paths.JWKS).permitAll()
                // Local admin login/status remain public for operational use
                .requestMatchers(
                    Paths.ADMIN_LOGIN,
                    Paths.ADMIN_STATUS
                ).permitAll()
                // All other requests require authentication
                .anyRequest().authenticated()
            )
            // Allow H2 console frames
            .headers(headers -> headers
                .frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
            // JWT filter authenticates all other API requests
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        log.info("CORS Config => allowedOrigins='{}', allowedMethods='{}', allowedHeaders='{}', exposeHeaders='{}', allowCredentials={}, maxAge={}",
                allowedOrigins, allowedMethods, allowedHeaders, exposeHeaders, allowCredentials, maxAge);
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        configuration.setAllowedMethods(Arrays.asList(allowedMethods.split(",")));
        if ("*".equals(allowedHeaders)) {
            configuration.setAllowedHeaders(List.of("*"));
        } else {
            configuration.setAllowedHeaders(Arrays.asList(allowedHeaders.split(",")));
        }
        configuration.setExposedHeaders(Arrays.asList(exposeHeaders.split(",")));
        configuration.setAllowCredentials(allowCredentials);
        configuration.setMaxAge(maxAge);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * Password encoder for local user authentication.
     *
     * <p>Wraps BCrypt in AES-GCM with a versioned application-wide pepper, so
     * pepper rotation can run transparently in the background (see
     * {@link PepperedPasswordEncoder} and {@code PasswordHashRotationService}).
     *
     * <p>Pepper keys come from the {@code PASSWORD_PEPPER_V*} environment
     * variables via {@link PasswordPepperProperties}; the active version comes
     * from {@code PASSWORD_PEPPER_ACTIVE_VERSION}. The pod fails to start if
     * no keys are configured or the active version has no matching key.
     */
    @Bean
    public PasswordEncoder passwordEncoder(PasswordPepperProperties props) {
        return new PepperedPasswordEncoder(props.getKeys(), props.getActiveVersion());
    }
}
