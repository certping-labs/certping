// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Records a refused or failed call of a controller method as a failure of {@link #value()}: what was
 * attempted, by whom, on what, and why it failed, as an
 * {@link AuditReason} code decided by the failure's type ({@link AuditReasons}), never its message.
 *
 * <p>{@link AuditFailureAspect} records it whatever refused the call:
 * <ul>
 *   <li>an exception from the method, including a {@code @PreAuthorize} denial and a {@code @FeatureGated}
 *       423, as the aspect runs outside method security, the feature gate and any transaction;</li>
 *   <li>a {@code ResponseEntity} the method returned with a 4xx or 5xx status;</li>
 *   <li>a request refused before the method ran (a {@code @Valid} body, an unreadable body, a bad
 *       parameter), which {@code GlobalExceptionHandler} reports through {@link AuditFailures}.</li>
 * </ul>
 *
 * <p>The SpEL expressions read the method's parameters by name ({@code #id}); before the method ran only
 * the path variables are known, by the same names. An expression that cannot be evaluated is left out and
 * the row is still written. A success is never recorded here: the service records it in the change's
 * transaction.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuditFailure {

    /** The event that failed: a customer event of the catalog, or an internal one (a platform setting). */
    AuditEventType value();

    /**
     * The target's id: a number is the resource id (and, for a member, its reference), anything else the
     * resource reference ({@code resource_ref}). Empty for none.
     */
    String target() default "";

    /** The target's display name, e.g. the feature key. Never stored for a member. Empty for none. */
    String name() default "";

    /** The domain the event concerns, e.g. the certificate's domain a deployment target is added to. Empty for none. */
    String domain() default "";

    /**
     * The organization whose trail the failure lands in, for a platform admin acting on a customer's
     * resource. Read for a super admin only: anyone else's failure lands in their own organization's trail,
     * whatever the request named. Empty, or nothing evaluated: the caller's organization; a caller with none
     * (platform staff) gets an internal row.
     */
    String organization() default "";

    /**
     * The event recorded instead of {@link #value()} when {@link #insteadWhen()} is true: one endpoint, two
     * events, e.g. turning single sign-on off rather than on. At most one; empty for none.
     */
    AuditEventType[] instead() default {};

    /** A boolean expression choosing {@link #instead()}; when it cannot be evaluated, {@link #value()} is used. */
    String insteadWhen() default "";
}
