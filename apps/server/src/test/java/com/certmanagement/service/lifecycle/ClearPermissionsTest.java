// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.security.Permissions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.stereotype.Component;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The (kind, action) → permission map of bulk clears: pinned to the permission each change needs one
 * record at a time, and complete for every action any registered lifecycle offers (deny by default
 * would otherwise silently hide a new action from everyone).
 */
class ClearPermissionsTest {

    @Test
    void eachBulkActionNeedsThePermissionOfTheSameChangeOneRecordAtATime() {
        assertRequires(BlockerKind.DEPLOYMENT_TARGETS, ClearAction.CLEAR_TARGETS, Permissions.CERTIFICATE_ISSUE);
        assertRequires(BlockerKind.AUTO_RENEW_CERTS, ClearAction.DISABLE_AUTO_RENEW, Permissions.CERTIFICATE_RENEW);
        assertRequires(BlockerKind.AUTO_RENEW_CERTS_ON_CA, ClearAction.DISABLE_AUTO_RENEW,
                Permissions.CERTIFICATE_RENEW);
        assertRequires(BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.CANCEL_ALL, Permissions.CERTIFICATE_DEPLOY);
    }

    @Test
    void featureFlagsManageAloneNeverPermitsABulkClear() {
        for (BlockerKind kind : BlockerKind.values()) {
            for (ClearAction action : ClearAction.values()) {
                assertThat(ClearPermissions.permits(kind, action, Set.of(Permissions.FEATURE_FLAGS_MANAGE)))
                        .as("%s %s", kind, action).isFalse();
            }
        }
    }

    @Test
    void linkOnlyKindsAndUnofferedActionsAreNeverPermitted() {
        Set<String> everything = Set.of(Permissions.CERTIFICATE_DEPLOY, Permissions.CERTIFICATE_ISSUE,
                Permissions.CERTIFICATE_RENEW, Permissions.FEATURE_FLAGS_MANAGE);
        for (ClearAction action : ClearAction.values()) {
            assertThat(ClearPermissions.permits(BlockerKind.ACTIVE_INTEGRATIONS, action, everything)).isFalse();
            assertThat(ClearPermissions.permits(BlockerKind.CREDENTIALS_IN_USE, action, everything)).isFalse();
            assertThat(ClearPermissions.permits(BlockerKind.PENDING_ISSUANCES, action, everything)).isFalse();
        }
        assertThat(ClearPermissions.permits(BlockerKind.RUNNING_DISCOVERY_SCANS, ClearAction.DELETE_ALL, everything))
                .isFalse();
    }

    @Test
    void withPermittedActionsKeepsEveryBlockerAndNarrowsOnlyItsActions() {
        Blocker scans = new Blocker(BlockerKind.RUNNING_DISCOVERY_SCANS, "Running discovery scans", 3,
                "/discovery", List.of(ClearAction.CANCEL_ALL));
        Blocker integrations = new Blocker(BlockerKind.ACTIVE_INTEGRATIONS, "Active integrations", 1,
                "/integrations/apps", List.of());

        assertThat(ClearPermissions.withPermittedActions(List.of(scans, integrations), Set.of()))
                .extracting(Blocker::kind, Blocker::count, Blocker::actions)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(BlockerKind.RUNNING_DISCOVERY_SCANS, 3L, List.of()),
                        org.assertj.core.groups.Tuple.tuple(BlockerKind.ACTIVE_INTEGRATIONS, 1L, List.of()));
        assertThat(ClearPermissions.withPermittedActions(List.of(scans), Set.of(Permissions.CERTIFICATE_DEPLOY)))
                .containsExactly(scans);
    }

    @Test
    void disableCheckOffersClearTargetsToWhoeverMayRemoveATarget_notToWhoeverMayOnlyDeploy() {
        Blocker targets = new Blocker(BlockerKind.DEPLOYMENT_TARGETS, "Deployment targets", 2,
                "/cert-manager/deployments", List.of(ClearAction.CLEAR_TARGETS));

        assertThat(ClearPermissions.withPermittedActions(List.of(targets), Set.of(Permissions.CERTIFICATE_ISSUE)))
                .singleElement().extracting(Blocker::actions).isEqualTo(List.of(ClearAction.CLEAR_TARGETS));
        assertThat(ClearPermissions.withPermittedActions(List.of(targets), Set.of(Permissions.CERTIFICATE_DEPLOY)))
                .singleElement().extracting(Blocker::actions).isEqualTo(List.of());
    }

    @Test
    void everyActionAnyLifecycleOffersHasAPermission() throws Exception {
        List<FeatureLifecycle> lifecycles = allLifecycles();
        assertThat(lifecycles).as("lifecycles found").hasSizeGreaterThanOrEqualTo(9);
        for (FeatureLifecycle lifecycle : lifecycles) {
            for (BlockerKind kind : lifecycle.kinds()) {
                for (ClearAction action : lifecycle.supportedActions(kind)) {
                    assertThat(ClearPermissions.requiredPermission(kind, action))
                            .as("%s offers %s on %s", lifecycle.featureKey(), action, kind).isPresent();
                }
            }
        }
    }

    private static void assertRequires(BlockerKind kind, ClearAction action, String permission) {
        assertThat(ClearPermissions.requiredPermission(kind, action)).contains(permission);
        assertThat(ClearPermissions.permits(kind, action, Set.of(permission))).isTrue();
    }

    /** Every {@code @Bean} lifecycle of the configuration and every lifecycle component, built on mocks. */
    private static List<FeatureLifecycle> allLifecycles() throws Exception {
        List<FeatureLifecycle> lifecycles = new ArrayList<>();
        FeatureLifecycleConfiguration configuration = new FeatureLifecycleConfiguration();
        for (Method method : FeatureLifecycleConfiguration.class.getDeclaredMethods()) {
            if (method.isAnnotationPresent(Bean.class)) {
                method.setAccessible(true);
                lifecycles.add((FeatureLifecycle) method.invoke(configuration, mocksFor(method.getParameterTypes())));
            }
        }
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AssignableTypeFilter(FeatureLifecycle.class));
        for (BeanDefinition candidate : scanner.findCandidateComponents(FeatureLifecycle.class.getPackageName())) {
            Class<?> type = Class.forName(candidate.getBeanClassName());
            if (!type.isAnnotationPresent(Component.class)) {
                continue;
            }
            Constructor<?> constructor = type.getDeclaredConstructors()[0];
            lifecycles.add((FeatureLifecycle) constructor.newInstance(mocksFor(constructor.getParameterTypes())));
        }
        return lifecycles;
    }

    private static Object[] mocksFor(Class<?>[] types) {
        return Arrays.stream(types).map(type -> (Object) mock(type)).toArray();
    }
}
