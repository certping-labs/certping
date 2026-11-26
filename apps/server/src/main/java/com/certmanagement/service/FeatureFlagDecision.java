// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;

/**
 * The single, pure feature flag decision. {@link FeatureFlagResolver} (one flag, cached) and
 * {@link FeatureFlagService#listEffective(Long)} (every flag for one org, batch-loaded) both feed
 * their rows into {@link #decide}, so the two can never disagree. {@link FeatureFlagService}
 * documents the precedence rules in prose; this class is their executable form.
 *
 * <p>No I/O: callers load the rows, this class only decides.
 */
public final class FeatureFlagDecision {

    static final String SCOPE_ORG = "ORG";

    private FeatureFlagDecision() {}

    /**
     * The {@code global_feature_flags} columns the decision reads. {@code category} is carried for the
     * callers that show it; it no longer decides anything.
     */
    public record GlobalRow(String featureKey, boolean enabled, String scope, String category) {}

    /** An {@code organization_feature_flags} row; {@code null} when the org has no override. */
    public record OrgOverride(boolean enabled, boolean adminLocked) {}

    /**
     * The outcome for one flag and one organization.
     *
     * @param effectiveEnabled whether the feature is on for the organization
     * @param orgOverridable   whether an org override (by anyone) can decide this flag for the org
     * @param orgControllable  whether the org admin may set it: overridable, not reserved to super
     *                         admins, and no super admin decision stands in the way
     */
    public record Outcome(boolean effectiveEnabled, boolean orgOverridable, boolean orgControllable) {}

    /**
     * Whether {@link #decide} can need the organization's rows. When this is {@code false} the
     * caller may pass {@code null} org inputs and skip loading them; the outcome is the same.
     */
    public static boolean needsOrgRows(GlobalRow global, Long orgId) {
        return orgId != null && isOrgScoped(global) && global.enabled();
    }

    /**
     * Decides one flag for one organization ({@code orgId == null} is the platform-level check that
     * crons and listeners make: no org rows).
     *
     * @param global         the global row; a caller with no row fails open before calling
     * @param orgId          the organization, or {@code null} for a platform-level check
     * @param orgType        the organization's type, or {@code null}; carried for callers, not decisive
     * @param orgOverride    the organization's override, or {@code null}
     * @param orgTypeEnabled the org-type default for the flag, or {@code null} when none is set
     * @return the outcome; never {@code null}
     */
    public static Outcome decide(GlobalRow global, Long orgId, String orgType,
                                 OrgOverride orgOverride, Boolean orgTypeEnabled) {
        if (!global.enabled()) {
            return new Outcome(false, false, false);
        }
        if (orgId == null || !isOrgScoped(global)) {
            return new Outcome(true, false, false);
        }
        Boolean orgEnabled = orgOverride == null ? null : orgOverride.enabled();
        boolean adminLocked = orgOverride != null && orgOverride.adminLocked();
        boolean orgControllable = !FeatureFlags.NOT_ORG_CONTROLLABLE.contains(global.featureKey())
                && !adminLocked
                && !Boolean.FALSE.equals(orgTypeEnabled);
        return new Outcome(decideForOrg(orgEnabled, adminLocked, orgTypeEnabled), true, orgControllable);
    }

    /**
     * The answer for a flag an organization override can decide, once the global check passes. A super admin's decision outranks the org admin's: an admin-locked org
     * override decides, then an org-type "off", then the org admin's override, and otherwise on.
     */
    static boolean decideForOrg(Boolean orgEnabled, boolean orgAdminLocked, Boolean orgTypeEnabled) {
        if (orgEnabled != null && orgAdminLocked) {
            return orgEnabled;
        }
        if (Boolean.FALSE.equals(orgTypeEnabled)) {
            return false;
        }
        return orgEnabled == null || orgEnabled;
    }

    /**
     * Which layer switched a flag off for an organization, in the precedence order of {@link #decide}:
     * the global switch, an org override (the super admin's locked one or the org admin's own), or the
     * org-type default. {@code REQUIREMENT}: the feature is
     * on, but the flag its automatic work also needs is off ({@link FeatureFlagInputs#automaticWorkOffCause}).
     */
    public enum OffCause { GLOBAL, ORG_OVERRIDE, ORG_TYPE, REQUIREMENT }

    /**
     * Why {@link #decide} answers "off" for these inputs, or {@code null} when it answers "on". Walks
     * the same branches in the same order, so a cause exists exactly when the effective state is off.
     */
    public static OffCause offCause(GlobalRow global, Long orgId, String orgType,
                                    OrgOverride orgOverride, Boolean orgTypeEnabled) {
        if (!global.enabled()) {
            return OffCause.GLOBAL;
        }
        if (orgId == null || !isOrgScoped(global)) {
            return null;
        }
        if (orgOverride != null && orgOverride.adminLocked()) {
            return orgOverride.enabled() ? null : OffCause.ORG_OVERRIDE;
        }
        if (Boolean.FALSE.equals(orgTypeEnabled)) {
            return OffCause.ORG_TYPE;
        }
        return orgOverride != null && !orgOverride.enabled() ? OffCause.ORG_OVERRIDE : null;
    }

    /** Whether org and org-type rows can decide the flag: ORG scope only. */
    static boolean isOrgScoped(GlobalRow global) {
        return SCOPE_ORG.equals(global.scope());
    }
}
