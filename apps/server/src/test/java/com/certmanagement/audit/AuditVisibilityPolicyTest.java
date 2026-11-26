// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.ResourceType;
import com.certmanagement.service.FeatureFlagService;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Options of features that are off are hidden, their events stay listed; super admins see all. */
class AuditVisibilityPolicyTest {

    private static final long ORG = 7L;

    private final FeatureFlagService flags = mock(FeatureFlagService.class);
    private final AuditVisibilityPolicy policy = new AuditVisibilityPolicy(flags);

    @Test
    void optionsOfAFeatureThatIsOffAreHiddenFromCustomers() {
        // Expectations come from the catalog, so events later PRs add keep the test true.
        String off = FeatureFlags.CREDENTIALS_MANAGEMENT;
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(off));
        AuditVisibilityPolicy.Viewer customer = policy.viewer(false, ORG);

        assertThat(policy.categories(customer)).extracting(AuditCategoryOption::key)
                .containsExactlyElementsOf(offered(off, e -> e.category().name()).stream()
                        .sorted(java.util.Comparator.comparing(AuditCategory::valueOf)).toList())
                .contains("ACCESS_CONTROL", "AUTHENTICATION", "ORGANIZATION");
        assertThat(policy.categories(customer)).allMatch(AuditCategoryOption::enabled);
        assertThat(policy.resourceTypes(customer))
                .containsExactlyElementsOf(offered(off, e -> e.resourceType().name()).stream().sorted().toList())
                .contains(ResourceType.USER.name());
        assertThat(policy.actions(customer))
                .containsExactlyElementsOf(offered(off, AuditEventType::action).stream().sorted().toList())
                .contains("USER_CREATED", "SIGN_IN", "DELETE");
        assertThat(hiddenOnlyBy(off, e -> e.resourceType().name())).as("the test hides something")
                .isNotEmpty().doesNotContainAnyElementsOf(policy.resourceTypes(customer));
    }

    /** The options of the customer events that are core or of a feature other than {@code off}. */
    private static Set<String> offered(String off, java.util.function.Function<AuditEventType, String> option) {
        return Arrays.stream(AuditEventType.values())
                .filter(e -> e.visibility() == AuditVisibility.CUSTOMER && e.category() != AuditCategory.ACCESS
                        && !off.equals(e.featureKey()))
                .map(option).collect(java.util.stream.Collectors.toSet());
    }

    private static Set<String> hiddenOnlyBy(String off, java.util.function.Function<AuditEventType, String> option) {
        Set<String> all = Arrays.stream(AuditEventType.values())
                .filter(e -> e.visibility() == AuditVisibility.CUSTOMER && e.category() != AuditCategory.ACCESS)
                .map(option).collect(java.util.stream.Collectors.toSet());
        all.removeAll(offered(off, option));
        return all;
    }

    @Test
    void anActionCodeOnlyAnOffFeatureUsesIsHidden() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(FeatureFlags.DISCOVERY));
        Set<String> hidden = hiddenOnlyBy(FeatureFlags.DISCOVERY, AuditEventType::action);

        assertThat(hidden).isNotEmpty();
        assertThat(policy.actions(policy.viewer(false, ORG))).doesNotContainAnyElementsOf(hidden);
        assertThat(policy.actions(policy.viewer(true, ORG))).containsAll(hidden);
    }

    @Test
    void aCategorySpanningAnOffAndAnOnFeatureStaysOffered() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(FeatureFlags.AGENT_HEALTH_MONITORING));

        AuditCategoryOption monitoring = policy.categories(policy.viewer(false, ORG)).stream()
                .filter(c -> c.key().equals("MONITORING")).findFirst().orElseThrow();
        assertThat(monitoring.enabled()).isTrue();
        assertThat(monitoring.featureKey()).as("alerts and agent health").isNull();
        assertThat(monitoring.label()).isEqualTo("Monitoring");
    }

    @Test
    void superAdminsSeeEveryCategoryMarkedWhetherItIsOnForTheOrganization() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT));

        List<AuditCategoryOption> categories = policy.categories(policy.viewer(true, ORG));

        assertThat(categories).filteredOn(c -> c.key().equals("CREDENTIALS")).singleElement()
                .satisfies(c -> {
                    assertThat(c.enabled()).isFalse();
                    assertThat(c.featureKey()).isEqualTo(FeatureFlags.CREDENTIALS_MANAGEMENT);
                });
        assertThat(policy.resourceTypes(policy.viewer(true, ORG))).contains(ResourceType.CREDENTIAL.name());
    }

    @Test
    void onlyCategoriesWithCustomerEventsAreOfferedInCatalogOrder() {
        List<String> keys = policy.categories(policy.viewer(true, null)).stream().map(AuditCategoryOption::key).toList();

        assertThat(keys).as("internal rows, and the Access view's sensitive reads").doesNotContain("PLATFORM", "ACCESS");
        List<String> catalogOrder = Arrays.stream(AuditCategory.values()).map(Enum::name).filter(keys::contains).toList();
        assertThat(keys).isEqualTo(catalogOrder);
        assertThat(keys).allSatisfy(key -> assertThat(Arrays.stream(AuditEventType.values())
                .anyMatch(e -> e.visibility() == AuditVisibility.CUSTOMER && e.category().name().equals(key))).isTrue());
        assertThat(keys).as("every category of the list's events is offered")
                .containsAll(AuditVisibilityPolicy.customerEvents().stream().map(e -> e.category().name()).toList());
    }

    @Test
    void eventsOfAFeatureThatIsOffAreMarkedNotHidden() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of(FeatureFlags.CREDENTIALS_MANAGEMENT));
        AuditVisibilityPolicy.Viewer customer = policy.viewer(false, ORG);

        assertThat(customer.hiddenFeatureKeys()).isEmpty();
        assertThat(customer.featureOff(FeatureFlags.CREDENTIALS_MANAGEMENT)).isTrue();
        assertThat(customer.featureOff(null)).as("core").isFalse();
        assertThat(customer.featureOff(FeatureFlags.DISCOVERY)).isFalse();
    }

    @Test
    void featureStatesAreLookedUpOncePerOrganizationPerReader() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of());
        AuditVisibilityPolicy.Viewer viewer = policy.viewer(true, null);

        viewer.featureOff(ORG, FeatureFlags.DISCOVERY);
        viewer.featureOff(ORG, FeatureFlags.CREDENTIALS_MANAGEMENT);
        assertThat(viewer.featureOff(null, FeatureFlags.DISCOVERY)).as("no organization: nothing is off").isFalse();

        verify(flags, times(1)).disabledFeatureKeys(ORG);
    }

    @Test
    void theActionsAndResourcesOfSensitiveReadsAreNotOptions() {
        when(flags.disabledFeatureKeys(ORG)).thenReturn(Set.of());
        Set<String> accessOnlyActions = Arrays.stream(AuditEventType.values())
                .filter(e -> e.category() == AuditCategory.ACCESS).map(AuditEventType::action)
                .filter(action -> AuditVisibilityPolicy.customerEvents().stream().noneMatch(e -> e.action().equals(action)))
                .collect(java.util.stream.Collectors.toSet());

        assertThat(accessOnlyActions).isNotEmpty();
        assertThat(policy.actions(policy.viewer(true, ORG))).doesNotContainAnyElementsOf(accessOnlyActions);
    }
}
