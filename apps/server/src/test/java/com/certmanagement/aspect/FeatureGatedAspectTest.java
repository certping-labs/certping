// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.aspect;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.FeatureFlagService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** Unit tests for {@link FeatureGatedAspect}. */
@ExtendWith(MockitoExtension.class)
class FeatureGatedAspectTest {

    @Mock private FeatureFlagService featureFlagService;
    @Mock private ProceedingJoinPoint joinPoint;
    @Mock private MethodSignature signature;

    private FeatureGatedAspect aspect;

    // ── Fixtures carrying real annotations resolvable via reflection ──
    @FeatureGated("class-flag")
    static class GatedClass {
        @FeatureGated("method-flag")
        public void annotatedMethod() { }

        public void unannotatedMethod() { }
    }

    static class PlainClass {
        public void noAnnotations() { }
    }

    @BeforeEach
    void setUp() {
        aspect = new FeatureGatedAspect(featureFlagService);
        GatewayRequestContext.clear();
    }

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    private Method method(Class<?> type, String name) throws Exception {
        return type.getMethod(name);
    }

    @Test
    void methodAnnotationTakesPrecedenceAndProceedsWhenEnabled() throws Throwable {
        Method m = method(GatedClass.class, "annotatedMethod");
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(m);
        when(joinPoint.proceed()).thenReturn("ok");

        Object result = aspect.checkFeatureFlag(joinPoint);

        assertThat(result).isEqualTo("ok");
        verify(featureFlagService).assertEnabled(eq("method-flag"), isNull());
        verify(joinPoint).proceed();
    }

    @Test
    void usesOrgIdFromGatewayContext() throws Throwable {
        GatewayRequestContext.set(7, "55", "req-1", "u@test");
        Method m = method(GatedClass.class, "annotatedMethod");
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(m);
        when(joinPoint.proceed()).thenReturn("ok");

        aspect.checkFeatureFlag(joinPoint);

        verify(featureFlagService).assertEnabled("method-flag", 55L);
    }

    @Test
    void fallsBackToClassAnnotationWhenMethodUnannotated() throws Throwable {
        Method m = method(GatedClass.class, "unannotatedMethod");
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(m);
        when(joinPoint.proceed()).thenReturn("ok");

        aspect.checkFeatureFlag(joinPoint);

        verify(featureFlagService).assertEnabled(eq("class-flag"), isNull());
    }

    @Test
    void proceedsWithoutCheckWhenNoAnnotationPresent() throws Throwable {
        Method m = method(PlainClass.class, "noAnnotations");
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(m);
        when(joinPoint.proceed()).thenReturn("ok");

        Object result = aspect.checkFeatureFlag(joinPoint);

        assertThat(result).isEqualTo("ok");
        verifyNoInteractions(featureFlagService);
    }

    @Test
    void propagatesFeatureDisabledExceptionWhenFlagOff() throws Throwable {
        Method m = method(GatedClass.class, "annotatedMethod");
        when(joinPoint.getSignature()).thenReturn(signature);
        when(signature.getMethod()).thenReturn(m);
        doThrow(new FeatureDisabledException("off"))
                .when(featureFlagService).assertEnabled(eq("method-flag"), isNull());

        assertThatThrownBy(() -> aspect.checkFeatureFlag(joinPoint))
                .isInstanceOf(FeatureDisabledException.class);
        verify(joinPoint, never()).proceed();
    }
}
