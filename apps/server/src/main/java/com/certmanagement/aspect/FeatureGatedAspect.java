// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.aspect;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.FeatureFlagService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;

/**
 * AOP aspect that enforces {@link FeatureGated} annotations on controller methods.
 *
 * <p>Resolves the organization ID from the JWT (null-safe; falls back to {@code null}
 * for super-admin calls that have no org context). Delegates to
 * {@link FeatureFlagService#assertEnabled(String, Long)}, which throws
 * {@link com.certmanagement.exception.FeatureDisabledException} if the flag is off.
 */
@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class FeatureGatedAspect {

    private final FeatureFlagService featureFlagService;

    // Match @FeatureGated on the method OR on the declaring class (@within).
    // Method-level annotation wins if both are present so a class-wide gate can be
    // selectively overridden per endpoint with a different (or no — by leaving the
    // method unannotated and dropping the class-level annotation if needed) flag.
    @Around("@annotation(com.certmanagement.annotation.FeatureGated) "
            + "|| @within(com.certmanagement.annotation.FeatureGated)")
    public Object checkFeatureFlag(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        FeatureGated methodAnn = signature.getMethod().getAnnotation(FeatureGated.class);
        FeatureGated classAnn  = signature.getMethod().getDeclaringClass().getAnnotation(FeatureGated.class);
        FeatureGated effective = methodAnn != null ? methodAnn : classAnn;
        if (effective == null) {
            // Defensive — pointcut should always give us one; if neither, just proceed.
            return joinPoint.proceed();
        }
        String featureKey = effective.value();

        Long orgId = OrgResolver.fromJwtOrNull();
        log.debug("Checking feature flag '{}' for orgId={} (source={})", featureKey, orgId,
                methodAnn != null ? "method" : "class");

        featureFlagService.assertEnabled(featureKey, orgId);

        return joinPoint.proceed();
    }
}
