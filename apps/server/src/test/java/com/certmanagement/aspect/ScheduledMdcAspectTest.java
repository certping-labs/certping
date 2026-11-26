// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.MDC;

import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/** Unit tests for {@link ScheduledMdcAspect}. */
@ExtendWith(MockitoExtension.class)
class ScheduledMdcAspectTest {

    @Mock private ProceedingJoinPoint pjp;
    @Mock private Signature signature;

    private final ScheduledMdcAspect aspect = new ScheduledMdcAspect();

    @BeforeEach
    @AfterEach
    void clear() {
        MDC.clear();
    }

    @Test
    void seedsRequestIdDuringInvocationAndRestoresAfter() throws Throwable {
        when(pjp.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("renewCerts");

        AtomicReference<String> seen = new AtomicReference<>();
        when(pjp.proceed()).thenAnswer(inv -> {
            seen.set(MDC.get("requestId"));
            return "done";
        });

        Object result = aspect.seedRequestIdForScheduledTick(pjp);

        assertThat(result).isEqualTo("done");
        assertThat(seen.get()).startsWith("req-sched-renewCerts-");
        // MDC restored to empty after the tick.
        assertThat(MDC.get("requestId")).isNull();
    }

    @Test
    void restoresPreviousMdcAfterInvocation() throws Throwable {
        MDC.put("requestId", "outer");
        when(pjp.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("job");
        when(pjp.proceed()).thenReturn(null);

        aspect.seedRequestIdForScheduledTick(pjp);

        assertThat(MDC.get("requestId")).isEqualTo("outer");
    }

    @Test
    void clearsMdcEvenWhenJoinPointThrows() throws Throwable {
        when(pjp.getSignature()).thenReturn(signature);
        when(signature.getName()).thenReturn("failing");
        when(pjp.proceed()).thenThrow(new IllegalStateException("boom"));

        assertThatThrownBy(() -> aspect.seedRequestIdForScheduledTick(pjp))
                .isInstanceOf(IllegalStateException.class);
        assertThat(MDC.get("requestId")).isNull();
    }
}
