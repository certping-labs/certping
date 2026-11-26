// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.FeatureFlags;

import java.util.Map;
import java.util.Set;

/**
 * The backend-owned permission → feature flag mapping: which feature a permission belongs to, so
 * the permission (and a role made only of such permissions) is hidden while that feature is off for
 * the organization. A permission with no feature ({@code null}) is core and always shown.
 *
 * <p>Kept in code rather than a column: the flags are code constants too, a new permission only
 * needs its resource listed here (a resource with no entry is core, the safe default for showing),
 * and {@code PermissionFeatureMapTest} pins every {@link Permissions} constant to its answer.
 *
 * <p>A permission that still authorizes an endpoint its feature does not gate must stay core, or
 * switching that feature off would hide (and block granting) a permission people still need:
 * <ul>
 *   <li>{@code certificate:deploy} also triggers discovery scans and cancels them in bulk
 *       (DISCOVERY), and unlocks private-key export (CERTIFICATE_DOWNLOAD);</li>
 *   <li>{@code credential:read} lists and reads credentials, which is not gated, and the discovery
 *       scan form picks its credential from that list.</li>
 * </ul>
 * The rest of their resources keep their feature: {@code credential:create/delete/rotate} stay with
 * CREDENTIALS_MANAGEMENT.
 */
public final class PermissionFeatureMap {

    private PermissionFeatureMap() {}

    /** Always shown whatever their resource maps to; see the class comment for why each is here. */
    private static final Set<String> CORE_OVERRIDES = Set.of(
            Permissions.CERTIFICATE_DEPLOY,
            Permissions.CREDENTIAL_READ);

    /** Certificate actions belong to different features; {@code certificate:read/delete/deploy} are core. */
    private static final Map<String, String> BY_PERMISSION = Map.of(
            Permissions.CERTIFICATE_ISSUE, FeatureFlags.CERTIFICATE_ISSUANCE,
            Permissions.CERTIFICATE_RENEW, FeatureFlags.CERTIFICATE_RENEWAL,
            Permissions.CERTIFICATE_REVOKE, FeatureFlags.CERTIFICATE_REVOCATION);

    /** Every other feature owns whole resources ({@code resource:action}). */
    private static final Map<String, String> BY_RESOURCE = Map.ofEntries(
            Map.entry("credential", FeatureFlags.CREDENTIALS_MANAGEMENT),
            Map.entry("alerts", FeatureFlags.ALERTS),
            Map.entry("agent-deep-health", FeatureFlags.AGENT_HEALTH_MONITORING),
            Map.entry("deployments", FeatureFlags.CERTIFICATE_DEPLOYMENT),
            Map.entry("iot_device", FeatureFlags.IOT_DEVICE_MANAGEMENT),
            Map.entry("iot_source", FeatureFlags.IOT_DEVICE_MANAGEMENT),
            Map.entry("iot_ca_health", FeatureFlags.IOT_DEVICE_MANAGEMENT),
            Map.entry("iot_certificate_profile", FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT),
            Map.entry("audit", FeatureFlags.AUDIT_LOGS));

    /**
     * The feature a permission belongs to.
     *
     * @param permissionName {@code resource:action}
     * @return the feature flag key, or {@code null} for a core permission (always shown)
     */
    public static String featureKeyOf(String permissionName) {
        if (permissionName == null || CORE_OVERRIDES.contains(permissionName)) {
            return null;
        }
        String exact = BY_PERMISSION.get(permissionName);
        if (exact != null) {
            return exact;
        }
        int separator = permissionName.indexOf(':');
        return separator < 0 ? null : BY_RESOURCE.get(permissionName.substring(0, separator));
    }
}
