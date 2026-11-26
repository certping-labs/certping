// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.service.FeatureFlagDecision.GlobalRow;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
import com.certmanagement.service.FeatureFlagDecision.OrgOverride;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link FeatureFlagDecision#offCause} names a cause exactly when {@link FeatureFlagDecision#decide}
 * says off, over every combination of the decision's inputs, and names the layer the precedence
 * rules give the last word.
 */
class FeatureFlagDecisionOffCauseTest {

    private static final List<OrgOverride> OVERRIDES = Arrays.asList(null, new OrgOverride(true, false),
            new OrgOverride(false, false), new OrgOverride(true, true), new OrgOverride(false, true));
    private static final List<Boolean> TYPE_DEFAULTS = Arrays.asList(null, true, false);

    @Test
    void aCauseExistsExactlyWhenTheDecisionIsOff() {
        int combinations = 0;
        for (GlobalRow global : globals()) {
            {
                for (Long orgId : Arrays.asList(null, 7L)) {
                    for (String orgType : Arrays.asList(null, "B2B")) {
                        for (OrgOverride override : OVERRIDES) {
                            for (Boolean typeDefault : TYPE_DEFAULTS) {
                                boolean on = FeatureFlagDecision.decide(global, orgId, orgType, override,
                                        typeDefault).effectiveEnabled();
                                OffCause cause = FeatureFlagDecision.offCause(global, orgId, orgType, override,
                                        typeDefault);
                                assertThat(cause == null).as("%s org=%s type=%s override=%s default=%s",
                                        global, orgId, orgType, override, typeDefault).isEqualTo(on);
                                combinations++;
                            }
                        }
                    }
                }
            }
        }
        assertThat(combinations).isGreaterThan(300);
    }

    @Test
    void theCauseIsTheLayerWithTheLastWord() {
        GlobalRow platformFlag = new GlobalRow("K", true, "ORG", "PLATFORM");

        assertThat(FeatureFlagDecision.offCause(new GlobalRow("K", false, "ORG", "PLATFORM"), 7L, "B2B",
                null, null)).isEqualTo(OffCause.GLOBAL);
        assertThat(FeatureFlagDecision.offCause(platformFlag, 7L, "B2B", new OrgOverride(false, false), false))
                .as("an org-type off outranks the org admin's own off").isEqualTo(OffCause.ORG_TYPE);
        assertThat(FeatureFlagDecision.offCause(platformFlag, 7L, "B2B", new OrgOverride(false, true), false))
                .as("a super admin's locked override outranks the org-type default").isEqualTo(OffCause.ORG_OVERRIDE);
        assertThat(FeatureFlagDecision.offCause(platformFlag, 7L, "B2B", new OrgOverride(false, false), null))
                .isEqualTo(OffCause.ORG_OVERRIDE);
    }

    private static List<GlobalRow> globals() {
        List<GlobalRow> rows = new ArrayList<>();
        for (boolean enabled : new boolean[] {true, false}) {
            for (String scope : List.of("ORG", "PLATFORM")) {
                for (String category : List.of("B2B", "PLATFORM")) {
                    rows.add(new GlobalRow("K", enabled, scope, category));
                }
            }
        }
        return rows;
    }
}
