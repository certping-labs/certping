// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Records a successful call of a controller method as a read of something sensitive: an
 * {@link AuditCategory#ACCESS} event, shown in the trail's separate Access
 * view. Only the reads this annotation marks are recorded; an ordinary page load is an application log line,
 * never an audit row.
 *
 * <p>{@link AuditedReads} groups the rows: one per organization, actor, event and target every
 * {@value AuditedReads#GROUP_MINUTES} minutes, so a page that polls, or a member opening the same secret ten
 * times, leaves one row. A read that failed (an exception, or a 4xx or 5xx {@code ResponseEntity}) is not a
 * read and records nothing; a refused attempt to read is not an access event.
 *
 * <p>The SpEL expressions read the method's parameters by name ({@code #organizationId}). An expression that
 * cannot be evaluated is left out and the row is still written. Rows go through the bounded async writer: a
 * read never waits for, or fails on, its audit row.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuditedRead {

    /** The read, an {@link AuditCategory#ACCESS} event of the catalog. */
    AuditEventType value();

    /**
     * What was read: a number is the resource id (and its reference), anything else the resource reference.
     * Empty for a read of the organization's whole collection (its CBOM, its audit log).
     */
    String target() default "";

    /**
     * The organization whose trail the read lands in, for a super admin reading a customer's data. Read for a
     * super admin only: anyone else's read lands in their own organization's trail. Empty, or nothing evaluated:
     * the caller's organization; a caller with none (platform staff reading no organization's data) gets an
     * internal row.
     */
    String organization() default "";
}
