// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Records the read a method annotated {@link AuditedRead} made, once it returned successfully: a returned
 * {@code ResponseEntity} with a 2xx or 3xx status, or any other return. A thrown failure is rethrown unchanged
 * and records nothing. Ordered with {@link AuditFailureAspect}, outside method security and the feature gate, so
 * a refused read never reaches the point where it would be recorded.
 */
@Aspect
@Component
@Order(AuditFailureAspect.ORDER + 1)
public class AuditedReadAspect {

    private final AuditedReads reads;

    public AuditedReadAspect(AuditedReads reads) {
        this.reads = reads;
    }

    @Around("@annotation(read)")
    public Object recordRead(ProceedingJoinPoint call, AuditedRead read) throws Throwable {
        Object result = call.proceed();
        if (result instanceof ResponseEntity<?> response && response.getStatusCode().value() >= 400) {
            return result;
        }
        reads.record(read, ((MethodSignature) call.getSignature()).getMethod(), call.getArgs());
        return result;
    }
}
