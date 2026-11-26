// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.enums.DevicePlatformType;

import java.util.Map;

/** Validated device-source metadata safe to publish outside the agent. */
public record DeviceSourceProfile(
        String profileRef,
        DevicePlatformType provider,
        String sourceCategory,
        String displayName,
        String description,
        Map<String, Object> metadata
) {}
