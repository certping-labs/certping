// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.security;

import com.certmanagement.constants.FeatureFlags;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/** Pins the answer for every permission constant, so a new permission is a deliberate decision. */
class PermissionFeatureMapTest {

    /** Permissions that belong to no feature and are always shown. */
    private static final Set<String> CORE = Set.of(
            Permissions.CERTIFICATE_READ, Permissions.CERTIFICATE_DELETE,
            Permissions.NOTIFICATIONS_VIEW,
            Permissions.USERS_MANAGE, Permissions.USERS_VIEW, Permissions.USERS_CREATE, Permissions.USERS_DELETE,
            Permissions.ROLES_MANAGE, Permissions.ROLES_VIEW, Permissions.ROLES_CREATE, Permissions.ROLES_DELETE,
            Permissions.ROLES_ASSIGN, Permissions.PERMISSIONS_VIEW, Permissions.PERMISSIONS_ASSIGN,
            Permissions.ORGANIZATION_VIEW, Permissions.ORGANIZATION_MANAGE,
            Permissions.FEATURE_FLAGS_VIEW, Permissions.FEATURE_FLAGS_MANAGE, Permissions.FEATURE_FLAGS_ADMINISTER,
            Permissions.INTEGRATIONS_VIEW, Permissions.INTEGRATIONS_MANAGE, Permissions.INCIDENTS_VIEW,
            Permissions.INCIDENTS_CREATE,
            // Core although their resource has a feature: each still authorizes an endpoint that
            // feature does not gate (discovery and key export; the ungated credential list), so
            // turning the feature off must not hide them.
            Permissions.CERTIFICATE_DEPLOY, Permissions.CREDENTIAL_READ);

    private static final Map<String, String> FEATURE_OF = new HashMap<>();

    static {
        FEATURE_OF.put(Permissions.CERTIFICATE_ISSUE, FeatureFlags.CERTIFICATE_ISSUANCE);
        FEATURE_OF.put(Permissions.CERTIFICATE_RENEW, FeatureFlags.CERTIFICATE_RENEWAL);
        FEATURE_OF.put(Permissions.DEPLOYMENTS_VIEW, FeatureFlags.CERTIFICATE_DEPLOYMENT);
        FEATURE_OF.put(Permissions.CERTIFICATE_REVOKE, FeatureFlags.CERTIFICATE_REVOCATION);
        FEATURE_OF.put(Permissions.AGENT_DEEP_HEALTH_READ, FeatureFlags.AGENT_HEALTH_MONITORING);
        FEATURE_OF.put(Permissions.ALERTS_VIEW, FeatureFlags.ALERTS);
        FEATURE_OF.put(Permissions.ALERTS_UPDATE, FeatureFlags.ALERTS);
        FEATURE_OF.put(Permissions.CREDENTIAL_CREATE, FeatureFlags.CREDENTIALS_MANAGEMENT);
        FEATURE_OF.put(Permissions.CREDENTIAL_DELETE, FeatureFlags.CREDENTIALS_MANAGEMENT);
        FEATURE_OF.put(Permissions.CREDENTIAL_ROTATE, FeatureFlags.CREDENTIALS_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_DEVICE_VIEW, FeatureFlags.IOT_DEVICE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_DEVICE_MANAGE, FeatureFlags.IOT_DEVICE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_SOURCE_VIEW, FeatureFlags.IOT_DEVICE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_SOURCE_MANAGE, FeatureFlags.IOT_DEVICE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_CA_HEALTH_VIEW, FeatureFlags.IOT_DEVICE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_CERTIFICATE_PROFILE_VIEW, FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_CERTIFICATE_PROFILE_MANAGE, FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT);
        FEATURE_OF.put(Permissions.IOT_CERTIFICATE_PROFILE_SYNC, FeatureFlags.IOT_CERTIFICATE_PROFILE_MANAGEMENT);
        FEATURE_OF.put(Permissions.AUDIT_VIEW, FeatureFlags.AUDIT_LOGS);
    }

    @Test
    void everyPermissionConstantIsEitherCoreOrMappedToItsFeature() {
        Set<String> constants = permissionConstants();
        Set<String> unclassified = constants.stream()
                .filter(name -> !CORE.contains(name) && !FEATURE_OF.containsKey(name))
                .collect(Collectors.toSet());
        assertThat(unclassified).as("classify new permissions in PermissionFeatureMap and this test").isEmpty();

        CORE.forEach(name -> assertThat(PermissionFeatureMap.featureKeyOf(name)).as(name).isNull());
        FEATURE_OF.forEach((name, feature) -> assertThat(PermissionFeatureMap.featureKeyOf(name)).as(name).isEqualTo(feature));
    }

    @Test
    void coreOverridesLeaveTheRestOfTheirResourceWithItsFeature() {
        assertThat(PermissionFeatureMap.featureKeyOf("audit:export")).isEqualTo(FeatureFlags.AUDIT_LOGS);
        assertThat(PermissionFeatureMap.featureKeyOf("credential:anything_new"))
                .isEqualTo(FeatureFlags.CREDENTIALS_MANAGEMENT);
    }

    @Test
    void unknownOrMalformedNamesAreCore() {
        assertThat(PermissionFeatureMap.featureKeyOf("brand_new:thing")).isNull();
        assertThat(PermissionFeatureMap.featureKeyOf("no-separator")).isNull();
        assertThat(PermissionFeatureMap.featureKeyOf(null)).isNull();
    }

    private static Set<String> permissionConstants() {
        return Arrays.stream(Permissions.class.getDeclaredFields())
                .filter(field -> Modifier.isStatic(field.getModifiers()) && field.getType() == String.class)
                .map(PermissionFeatureMapTest::valueOf)
                .filter(value -> value.contains(":"))
                .collect(Collectors.toSet());
    }

    private static String valueOf(Field field) {
        try {
            return (String) field.get(null);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
