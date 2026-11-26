// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a controller method as gated by a feature flag.
 *
 * <p>The {@link com.certmanagement.aspect.FeatureGatedAspect} intercepts any method annotated
 * with {@code @FeatureGated} and calls {@link com.certmanagement.service.FeatureFlagService#assertEnabled}
 * before the method body executes. The organization ID is resolved from the JWT via
 * {@link com.certmanagement.security.OrgResolver#fromJwtOrNull()}.
 *
 * <p>If the flag is disabled, the aspect throws a
 * {@link com.certmanagement.exception.FeatureDisabledException}, which is mapped to
 * {@code HTTP 423 Locked} by {@link com.certmanagement.exception.GlobalExceptionHandler}.
 *
 * <p>Usage:
 * <pre>{@code
 * @PostMapping(Paths.CERTS_ISSUE)
 * @FeatureGated(FeatureFlags.CERTIFICATE_ISSUANCE)
 * @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
 * public ResponseEntity<...> issue(...) { ... }
 * }</pre>
 */
/**
 * Can be applied to either a controller method (gates that one endpoint) OR a controller
 * class (gates every endpoint in the class with the same flag). Method-level annotations
 * take precedence over class-level when both are present.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface FeatureGated {

    /**
     * The feature flag key to check. Use constants from
     * {@link com.certmanagement.constants.FeatureFlags}.
     */
    String value();
}
