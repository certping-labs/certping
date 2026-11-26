// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter;

import com.certping.agent.model.enums.TargetType;

import java.lang.annotation.*;

/**
 * Marks a {@link DeploymentAdapter} implementation as the handler for one or more target types.
 * {@link DeploymentAdapterFactory} discovers adapters at startup by scanning this annotation
 * instead of using an explicit switch statement.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DeploymentAdapterFor {
    TargetType[] value();
}
