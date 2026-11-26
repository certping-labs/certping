// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.enums.DevicePlatformType;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a {@link DeviceIdentityConnector} as the handler for one or more platforms.
 * {@link DeviceIdentityConnectorFactory} discovers connectors by scanning this annotation,
 * following the same pattern as {@code DiscoveryAdapterFor}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface DeviceIdentityConnectorFor {
    DevicePlatformType[] value();
}
