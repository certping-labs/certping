// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery;

import com.certping.agent.model.enums.TargetType;

import java.lang.annotation.*;

/**
 * Marks a {@link DiscoveryAdapter} implementation as the handler for one or more target types.
 * {@link DiscoveryAdapterFactory} discovers adapters at startup by scanning this annotation.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DiscoveryAdapterFor {
    TargetType[] value();
}
