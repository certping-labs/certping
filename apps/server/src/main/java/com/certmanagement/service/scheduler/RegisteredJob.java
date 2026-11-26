// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Names the {@link JobPolicy} entry a {@code @Scheduled} method runs under. Every
 * {@code @Scheduled} method carries one (and every {@link DrainableCron} a {@link CronJobFor});
 * {@code JobPolicyRegistrationTest} fails the build when one is missing or names an unknown job, so a
 * new background job cannot skip declaring its tier and flags.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RegisteredJob {

    /** The {@link JobPolicy#jobName()} this method runs under. */
    String value();
}
