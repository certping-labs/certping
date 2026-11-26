// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

public record GcpTargetProxyConfig(String projectId, String location, String targetProxyName) {

    public boolean isGlobal() {
        return isGlobalLocation(location);
    }

    static boolean isGlobalLocation(String location) {
        return location == null || location.isBlank() || "global".equalsIgnoreCase(location);
    }
}
