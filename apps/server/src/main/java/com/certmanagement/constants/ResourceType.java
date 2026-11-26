// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.constants;

/**
 * ResourceType values mapped to the authoritative path constants in `Paths`.
 * This keeps URL prefixes consistent and avoids duplication.
 */
public enum ResourceType {
    CERTIFICATE(Paths.CERTS_BASE),
    DEPLOYMENT(Paths.DEPLOYMENTS_BASE),
    CREDENTIAL(Paths.CERT_CREDS_BASE),
    ROLE(Paths.ROLES_BASE),
    PERMISSION(Paths.PERMISSIONS_BASE),
    ORGANIZATION(Paths.ORGANIZATIONS_BASE),
    USER(Paths.USERS_BASE),
    ADMIN(Paths.ADMIN_BASE),
    NOTIFICATION(Paths.NOTIFICATIONS_BASE),
    ALERT(Paths.ALERTS),
    AUTH(Paths.AUTH_BASE),
    AUDIT(Paths.AUDIT_LOGS),
    INTEGRATION(Paths.INTEGRATIONS_BASE),
    INCIDENT(Paths.INCIDENTS_BASE),
    FEATURE_FLAG(Paths.FEATURE_FLAGS),
    // Audit targets only. No prefix, so the request interceptor's rows keep the resource their path gives
    // them; these name what an audit_events row is about.
    AGENT(""),
    DISCOVERY(""),
    IOT_DEVICE(""),
    IOT_SOURCE(""),
    IOT_CERTIFICATE(""),
    IOT_PROFILE(""),
    API("");

    private final String prefix;

    ResourceType(String prefix) {
        this.prefix = prefix;
    }

    public String getPrefix() {
        return prefix;
    }

    /**
     * Return the first enum whose prefix matches the start of the given path.
     * Declaration order is significant — earlier entries win for overlapping prefixes.
     */
    public static ResourceType fromPath(String path) {
        if (path == null) return API;
        for (ResourceType rt : ResourceType.values()) {
            String p = rt.getPrefix();
            if (p != null && !p.isEmpty() && path.startsWith(p)) {
                return rt;
            }
        }
        return API;
    }
}
