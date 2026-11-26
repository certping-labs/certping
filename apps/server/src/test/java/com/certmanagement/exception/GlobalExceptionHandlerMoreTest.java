// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import com.certmanagement.dto.common.ErrorResponse;
import com.certmanagement.support.common.ApiException;
import tools.jackson.databind.json.JsonMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.BindingResult;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerMoreTest {

    private GlobalExceptionHandler handler;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler(JsonMapper.builderWithJackson2Defaults().build());
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/test");
    }

    // ── Simple 1:1 status handlers ───────────────────────────────────────────

    @Test
    void resourceNotFound_mapsTo404() {
        var resp = handler.handleResourceNotFound(new ResourceNotFoundException("nope"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(resp.getBody().getMessage()).isEqualTo("nope");
        assertThat(resp.getBody().getPath()).isEqualTo("/api/v1/test");
    }

    @Test
    void duplicateResource_mapsTo409() {
        var resp = handler.handleDuplicateResource(new DuplicateResourceException("dup"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(resp.getBody().getMessage()).isEqualTo("dup");
    }

    @Test
    void unauthorized_mapsTo401() {
        var resp = handler.handleUnauthorized(new UnauthorizedException("no token"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getBody().getMessage()).isEqualTo("no token");
    }

    @Test
    void forbidden_mapsTo403() {
        var resp = handler.handleForbidden(new ForbiddenException("denied"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(resp.getBody().getMessage()).isEqualTo("denied");
    }

    @Test
    void ssoAuthentication_mapsTo401() {
        var resp = handler.handleSsoAuthenticationException(new SsoAuthenticationException("sso auth"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getBody().getMessage()).isEqualTo("sso auth");
    }

    @Test
    void ssoValidation_mapsTo401() {
        var resp = handler.handleSsoValidationException(new SsoValidationException("sso valid"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getBody().getMessage()).isEqualTo("sso valid");
    }

    @Test
    void authenticationException_mapsTo401WithGenericMessage() {
        AuthenticationException ex = new AuthenticationException("internal detail") {};
        var resp = handler.handleAuthenticationException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getBody().getMessage()).isEqualTo("Authentication required");
    }

    @Test
    void accessDenied_mapsTo403WithGenericMessage() {
        var resp = handler.handleAccessDenied(new AccessDeniedException("internal detail"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(resp.getBody().getMessage()).isEqualTo("Insufficient permissions");
    }

    @Test
    void illegalArgument_mapsTo400() {
        // A library's or parser's message can name internals: the caller gets a generic 400.
        var resp = handler.handleIllegalArgument(
                new IllegalArgumentException("No enum constant com.certmanagement.internal.Secret.X"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getMessage()).isEqualTo("The request is invalid").doesNotContain("certmanagement");
    }

    @Test
    void noResourceFound_mapsTo404() {
        NoResourceFoundException ex = new NoResourceFoundException(org.springframework.http.HttpMethod.GET, "/missing", "");
        var resp = handler.handleNoResourceFound(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(resp.getBody().getMessage()).isEqualTo("Resource not found");
    }

    @Test
    void unsupportedMethod_mapsTo405WithAllow() {
        var resp = handler.handleMethodNotSupported(
                new HttpRequestMethodNotSupportedException("POST", List.of("GET")), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(resp.getHeaders().getAllow()).containsExactly(org.springframework.http.HttpMethod.GET);
        assertThat(resp.getBody().getMessage()).isEqualTo("Request method not supported");
    }

    @Test
    void throwable_mapsTo500() {
        var resp = handler.handleThrowable(new Throwable("boom"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(resp.getBody().getMessage()).isEqualTo("An unexpected error occurred");
    }

    // ── FeatureDisabled alternate ctor ───────────────────────────────────────

    @Test
    void featureDisabled_customCodeAndMessage() {
        FeatureDisabledException ex = new FeatureDisabledException("KEY", "MY_CODE", "custom msg");
        ResponseEntity<Object> resp = handler.handleFeatureDisabled(ex, request);
        @SuppressWarnings("unchecked")
        java.util.Map<String, Object> body = (java.util.Map<String, Object>) resp.getBody();
        assertThat(body.get("code")).isEqualTo("MY_CODE");
        assertThat(body.get("message")).isEqualTo("custom msg");
        assertThat(body.get("feature")).isEqualTo("KEY");
        assertThat(body.get("path")).isEqualTo("/api/v1/test");
    }

    // ── Parameter / header / type-mismatch handlers ──────────────────────────

    @Test
    void methodArgumentTypeMismatch_includesParamName() {
        MethodArgumentTypeMismatchException ex =
                new MethodArgumentTypeMismatchException("abc", Integer.class, "page", null, null);
        var resp = handler.handleMethodArgumentTypeMismatch(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getMessage()).contains("page");
    }

    @Test
    void missingServletRequestParameter_includesParamName() {
        MissingServletRequestParameterException ex =
                new MissingServletRequestParameterException("orgId", "Long");
        var resp = handler.handleMissingServletRequestParameter(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getMessage()).contains("orgId");
    }

    @Test
    void missingRequestHeader_includesHeaderName() throws Exception {
        var methodParam = new org.springframework.core.MethodParameter(
                DummyController.class.getDeclaredMethod("handle", String.class), 0);
        MissingRequestHeaderException ex = new MissingRequestHeaderException("X-Org-Id", methodParam);
        var resp = handler.handleMissingRequestHeader(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getMessage()).contains("X-Org-Id");
    }

    static class DummyController {
        @SuppressWarnings("unused")
        void handle(String header) {}
    }

    // ── Validation handlers ──────────────────────────────────────────────────

    @Test
    void methodArgumentNotValid_collectsFieldErrors() {
        BindingResult br = new BeanPropertyBindingResult(new Object(), "obj");
        br.rejectValue(null, "code", "object error"); // global; field errors via addError
        br.addError(new org.springframework.validation.FieldError("obj", "email", "bad", false,
                null, null, "must be valid"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(
                (org.springframework.core.MethodParameter) null, br);
        var resp = handler.handleValidationErrors(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getError()).isEqualTo("Validation Failed");
        assertThat(resp.getBody().getFieldErrors()).extracting(ErrorResponse.FieldError::getField)
                .contains("email");
    }

    @Test
    void methodArgumentNotValid_redactsRejectedAuthCode() {
        BindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new org.springframework.validation.FieldError(
                "request", "authCode", "sensitive-epp-value", false,
                null, null, "must not exceed 255 characters"));
        MethodArgumentNotValidException exception = new MethodArgumentNotValidException(
                (org.springframework.core.MethodParameter) null, bindingResult);

        var response = handler.handleValidationErrors(exception, request);

        assertThat(response.getBody().getFieldErrors()).singleElement().satisfies(fieldError -> {
            assertThat(fieldError.getField()).isEqualTo("authCode");
            assertThat(fieldError.getRejectedValue()).isEqualTo("[REDACTED]");
        });
    }

    @Test
    void constraintViolation_collectsFieldErrors() {
        ConstraintViolation<?> v = mock(ConstraintViolation.class);
        jakarta.validation.Path path = mock(jakarta.validation.Path.class);
        when(path.toString()).thenReturn("create.arg0.email");
        when(v.getPropertyPath()).thenReturn(path);
        when(v.getMessage()).thenReturn("must not be blank");
        when(v.getInvalidValue()).thenReturn("");
        Set<ConstraintViolation<?>> set = new HashSet<>();
        set.add(v);
        ConstraintViolationException ex = new ConstraintViolationException(set);
        var resp = handler.handleConstraintViolation(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getFieldErrors()).hasSize(1);
        assertThat(resp.getBody().getFieldErrors().get(0).getField()).isEqualTo("create.arg0.email");
    }

    @Test
    void constraintViolation_nullPathFallsBackToRequest() {
        ConstraintViolation<?> v = mock(ConstraintViolation.class);
        when(v.getPropertyPath()).thenReturn(null);
        when(v.getMessage()).thenReturn("invalid");
        when(v.getInvalidValue()).thenReturn(null);
        Set<ConstraintViolation<?>> set = new HashSet<>();
        set.add(v);
        var resp = handler.handleConstraintViolation(new ConstraintViolationException(set), request);
        assertThat(resp.getBody().getFieldErrors().get(0).getField()).isEqualTo("request");
    }

    // ── ResponseStatus / ErrorResponse exceptions ────────────────────────────

    @Test
    void responseStatusException_nullReasonUsesReasonPhrase() {
        ResponseStatusException ex = new ResponseStatusException(HttpStatus.FORBIDDEN);
        var resp = handler.handleResponseStatusException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(resp.getBody().getMessage()).isEqualTo("Forbidden");
    }

    @Test
    void responseStatusException_keepsItsRetryAfterHeader() {
        ResponseStatusException ex = com.certmanagement.messaging.transport.AgentGatewayLimits
                .tooManyRequests("slow down", 12);
        var resp = handler.handleResponseStatusException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(resp.getHeaders().getFirst("Retry-After")).isEqualTo("12");
    }

    @Test
    void errorResponseException_usesDetailWhenPresent() {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "the detail");
        ErrorResponseException ex = new ErrorResponseException(HttpStatus.BAD_REQUEST, pd, null);
        var resp = handler.handleErrorResponseException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody().getMessage()).isEqualTo("the detail");
    }

    @Test
    void errorResponseException_nullDetailUsesReasonPhrase() {
        ErrorResponseException ex = new ErrorResponseException(HttpStatus.NOT_FOUND);
        var resp = handler.handleErrorResponseException(ex, request);
        assertThat(resp.getBody().getMessage()).isEqualTo("Not Found");
    }

    // ── Support ApiException ─────────────────────────────────────────────────

    @Test
    void supportApiException_resolvableStatus() {
        ApiException ex = new ApiException(404, "NOT_FOUND", "support not found");
        var resp = handler.handleSupportApiException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(resp.getBody().getMessage()).isEqualTo("support not found");
    }

    @Test
    void supportApiException_unresolvableStatusFallsBackTo500() {
        ApiException ex = new ApiException(799, "WEIRD", "weird status");
        var resp = handler.handleSupportApiException(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // ── DataIntegrityViolation friendly mapping ──────────────────────────────

    @Test
    void dataIntegrity_emailUniqueIndex() {
        var ex = new DataIntegrityViolationException("err",
                new RuntimeException("violates unique constraint \"uk_users_email_global\""));
        var resp = handler.handleDataIntegrityViolation(ex, request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(resp.getBody().getMessage()).isEqualTo("A user with this email already exists.");
    }

    @Test
    void dataIntegrity_usernameUniqueIndex() {
        var ex = new DataIntegrityViolationException("err",
                new RuntimeException("uk_users_username dup"));
        var resp = handler.handleDataIntegrityViolation(ex, request);
        assertThat(resp.getBody().getMessage()).isEqualTo("A user with this username already exists.");
    }

    @Test
    void dataIntegrity_genericDuplicateKey() {
        var ex = new DataIntegrityViolationException("err",
                new RuntimeException("duplicate key value blah"));
        var resp = handler.handleDataIntegrityViolation(ex, request);
        assertThat(resp.getBody().getMessage()).isEqualTo("This record already exists.");
    }

    @Test
    void dataIntegrity_unknownCauseGenericMessage() {
        var ex = new DataIntegrityViolationException("err", new RuntimeException("something else"));
        var resp = handler.handleDataIntegrityViolation(ex, request);
        assertThat(resp.getBody().getMessage())
                .isEqualTo("The request conflicts with the current state of the resource.");
    }
}
