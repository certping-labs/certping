// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Records the failure of a method annotated {@link AuditFailure}. It is ordered outside every other
 * advice on the method: Spring Security's method security ({@code @PreAuthorize}, order 200),
 * {@code FeatureGatedAspect} and {@code @Transactional} (both lowest precedence). So a permission denial
 * and a switched-off feature are recorded like any other refusal, and the row is queued after a
 * transaction around the method has rolled back. A failure is rethrown unchanged; a returned
 * {@code ResponseEntity} with a 4xx or 5xx status is recorded and returned unchanged.
 */
@Aspect
@Component
@Order(AuditFailureAspect.ORDER)
public class AuditFailureAspect {

    /**
     * Before every other advice but Spring's {@code ExposeInvocationInterceptor} ({@code HIGHEST_PRECEDENCE + 1}),
     * which must run first for the annotation to be bound as an argument.
     */
    static final int ORDER = Ordered.HIGHEST_PRECEDENCE + 100;

    private final AuditFailures failures;

    public AuditFailureAspect(AuditFailures failures) {
        this.failures = failures;
    }

    @Around("@annotation(failure)")
    public Object recordFailure(ProceedingJoinPoint call, AuditFailure failure) throws Throwable {
        Object result;
        try {
            result = call.proceed();
        } catch (Throwable thrown) {
            failures.record(failure, ((MethodSignature) call.getSignature()).getMethod(), call.getArgs(),
                    AuditReasons.of(thrown));
            throw thrown;
        }
        if (result instanceof ResponseEntity<?> response) {
            AuditReason reason = AuditReasons.ofStatus(response.getStatusCode().value());
            if (reason != null) {
                failures.record(failure, ((MethodSignature) call.getSignature()).getMethod(), call.getArgs(), reason);
            }
        }
        return result;
    }
}
