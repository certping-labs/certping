// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.FeatureDisabledException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.FeatureFlagChangeAudit;
import com.certmanagement.service.audit.FeatureFlagChangeAudit.OverrideState;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import com.certmanagement.service.lifecycle.ForcedFlagChanges;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;
import java.util.stream.Collectors;

import static com.certmanagement.config.CacheConfig.FEATURE_FLAGS;

/**
 * Core feature flag resolution and management service.
 *
 * <p><b>Resolution algorithm</b> (see {@link #isEnabled(String, Long)}):
 * <ol>
 *   <li>If the {@code global_feature_flags} row is missing → fail-open (return {@code true}).</li>
 *   <li>If {@code global.enabled = false} → return {@code false} for all orgs (kill switch).</li>
 *   <li>If {@code orgId == null} → return {@code true} (platform-level check; no org context for
 *       overrides).</li>
 *   <li>If {@code scope = PLATFORM} → return {@code true} (org-level rows never decide these).</li>
 *   <li>If a super admin set an override for this org ({@code admin_locked}) → use it.</li>
 *   <li>If the org-type default is {@code false} → {@code false}.</li>
 *   <li>If the org admin set an override → use it.</li>
 *   <li>Otherwise → default {@code true}.</li>
 * </ol>
 *
 * <p>So a super admin's "off", per org or per org type, cannot be undone by an org admin, and an org
 * admin cannot change or remove a super admin's per-org override. An org-type "on" is only a default:
 * the org admin may still switch the feature off for their organization.
 *
 * <p>{@link FeatureFlagDecision} is the one executable form of these rules: {@link FeatureFlagResolver}
 * (single flag, cached) and {@link #listEffective(Long)} (every flag for one org, batch-loaded) both
 * call it. Every write here evicts the resolver's cache and is audited through
 * {@link FeatureFlagChangeAudit} in the same transaction, with the operator's reason.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FeatureFlagService {

    private static final String SCOPE_ORG      = "ORG";

    private final GlobalFeatureFlagRepository       globalRepo;
    private final OrganizationFeatureFlagRepository orgRepo;
    private final OrgTypeFeatureFlagRepository      orgTypeRepo;
    private final OrganizationRepository            organizationRepo;

    private final FeatureFlagResolver               resolver;
    private final ApplicationEventPublisher         events;
    private final FeatureFlagChangeAudit            changeAudit;
    // Resolved per call, never at construction: both reach FeatureLifecycleRegistry, whose
    // lifecycles need beans that inject this service, so holding them directly is a startup
    // cycle. FullApplicationContextTest guards it.
    private final ObjectProvider<FeatureLifecycleService> lifecycleServiceProvider;
    private final ObjectProvider<ForcedFlagChanges>       forcedChangesProvider;

    /** Every organization is of this one type; the org-type defaults are kept under it. */
    public static final String ORG_TYPE = "B2B";
    private static final java.util.Set<String> VALID_ORG_TYPES = java.util.Set.of(ORG_TYPE);
    /** Organizations per override query in {@link #listEffectiveForOrganizations}. */
    static final int OVERRIDE_CHUNK = 1000;

    private void assertValidOrgType(String orgType) {
        if (!VALID_ORG_TYPES.contains(orgType)) {
            throw new BadRequestException("Invalid orgType '" + orgType + "'. Must be " + ORG_TYPE + ".");
        }
    }

    /**
     * Resolves the effective enabled state for {@code featureKey} in the context of {@code orgId}.
     *
     * @param featureKey the flag key (use constants from {@link com.certmanagement.constants.FeatureFlags})
     * @param orgId      the organization id; may be {@code null} for platform-level checks
     * @return {@code true} if the feature is enabled for this org, {@code false} otherwise
     */
    public boolean isEnabled(String featureKey, Long orgId) {
        return resolver.resolve(featureKey, orgId);
    }

    /**
     * Throws {@link FeatureDisabledException} if the flag is disabled for this org.
     */
    public void assertEnabled(String featureKey, Long orgId) {
        if (!isEnabled(featureKey, orgId)) {
            throw new FeatureDisabledException(featureKey);
        }
    }

    /**
     * Throws {@link FeatureDisabledException} if a CA-specific flag is disabled, using a
     * CA_DISABLED error code to allow the frontend to show a more specific message.
     */
    public void assertCaEnabled(String caFeatureKey, Long orgId) {
        if (!isEnabled(caFeatureKey, orgId)) {
            throw new FeatureDisabledException(
                    caFeatureKey,
                    "CA_DISABLED",
                    "Certificate Authority '" + caFeatureKey + "' is currently disabled for this organization.");
        }
    }

    // ── Read ─────────────────────────────────────────────────────────────

    /** Returns all global flags. */
    public List<GlobalFeatureFlag> listGlobal() {
        return globalRepo.findAll();
    }

    /** Returns a single global flag or throws 404. */
    public GlobalFeatureFlag getGlobal(String featureKey) {
        return globalRepo.findByFeatureKey(featureKey)
                .orElseThrow(() -> new ResourceNotFoundException("Feature flag not found: " + featureKey));
    }

    /**
     * Returns all effective flags for an org — each entry reflects the resolved enabled state.
     * Three queries regardless of the catalog size (globals, the org's overrides, its org-type
     * defaults) plus the org type; every decision comes from {@link FeatureFlagDecision}, the same
     * function {@link #isEnabled(String, Long)} uses.
     *
     * @param orgId the organization; required (platform-level checks go through {@link #isEnabled})
     */
    public List<ResolvedFlag> listEffective(Long orgId) {
        Objects.requireNonNull(orgId, "orgId");
        List<GlobalFeatureFlag> globals = globalRepo.findAll();
        Map<String, OrganizationFeatureFlag> orgOverrides = orgRepo
                .findAllByOrganizationId(orgId)
                .stream()
                .collect(Collectors.toMap(OrganizationFeatureFlag::getFeatureKey, f -> f));

        String orgType = resolveOrgType(orgId);
        Map<String, OrgTypeFeatureFlag> typeOverrides = orgType != null
                ? orgTypeRepo.findAllByOrgType(orgType).stream()
                        .collect(Collectors.toMap(OrgTypeFeatureFlag::getFeatureKey, f -> f))
                : Map.of();

        return withAutomaticWorkPausedBy(globals.stream()
                .map(g -> resolveForOrg(g, orgId, orgType,
                        orgOverrides.get(g.getFeatureKey()), typeOverrides.get(g.getFeatureKey())))
                .toList());
    }

    /**
     * {@link #listEffective} for many organizations: the globals and org-type defaults once, the
     * organizations' overrides in chunks of {@value #OVERRIDE_CHUNK}, so the query count grows with the
     * chunk count instead of one round per organization.
     *
     * @param orgTypeById each organization's id and type (null type: unknown)
     * @return per organization, every flag resolved, in the same order as {@link #listEffective}
     */
    public Map<Long, List<ResolvedFlag>> listEffectiveForOrganizations(Map<Long, String> orgTypeById) {
        List<GlobalFeatureFlag> globals = globalRepo.findAll();
        Map<String, Map<String, OrgTypeFeatureFlag>> typeOverrides = orgTypeRepo.findAll().stream()
                .collect(Collectors.groupingBy(OrgTypeFeatureFlag::getOrgType,
                        Collectors.toMap(OrgTypeFeatureFlag::getFeatureKey, f -> f, (a, b) -> a)));
        Map<Long, Map<String, OrganizationFeatureFlag>> overrides = new HashMap<>();
        List<Long> ids = List.copyOf(orgTypeById.keySet());
        for (int from = 0; from < ids.size(); from += OVERRIDE_CHUNK) {
            orgRepo.findAllByOrganizationIdIn(ids.subList(from, Math.min(ids.size(), from + OVERRIDE_CHUNK)))
                    .forEach(o -> overrides.computeIfAbsent(o.getOrganizationId(), id -> new HashMap<>())
                            .put(o.getFeatureKey(), o));
        }
        Map<Long, List<ResolvedFlag>> resolved = new java.util.LinkedHashMap<>();
        orgTypeById.forEach((orgId, orgType) -> {
            Map<String, OrganizationFeatureFlag> orgOverrides = overrides.getOrDefault(orgId, Map.of());
            Map<String, OrgTypeFeatureFlag> defaults = orgType == null ? Map.of()
                    : typeOverrides.getOrDefault(orgType, Map.of());
            resolved.put(orgId, withAutomaticWorkPausedBy(globals.stream()
                    .map(g -> resolveForOrg(g, orgId, orgType,
                            orgOverrides.get(g.getFeatureKey()), defaults.get(g.getFeatureKey())))
                    .toList()));
        });
        return resolved;
    }

    /**
     * Every flag's effective state for an organization, from the resolver's cached per-organization
     * decision ({@link FeatureFlagResolver#effectiveMap}); every flag write and cross-pod change
     * clears it.
     *
     * @param orgId the organization; required
     * @return an immutable map of feature key to effective state
     */
    public Map<String, Boolean> effectiveMap(Long orgId) {
        return resolver.effectiveMap(orgId);
    }

    /**
     * The feature keys switched off for an organization, derived from the same cached decision as
     * {@link #effectiveMap}. Used to hide the permissions and roles of disabled features.
     *
     * @param orgId the organization; required
     * @return an immutable set of feature keys whose effective state is off
     */
    public Set<String> disabledFeatureKeys(Long orgId) {
        return resolver.effectiveMap(orgId).entrySet().stream()
                .filter(entry -> !entry.getValue())
                .map(Map.Entry::getKey)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Which of {@code featureKeys} are off, for each of a page of organizations: {@link
     * FeatureFlagResolver#resolveForOrganizations} per key, so four uncached queries per feature key
     * however many organizations there are. For pages that span many organizations (the platform's view
     * of the audit trail), where {@link #disabledFeatureKeys(Long)} would cost four queries per
     * organization on a cold cache.
     *
     * @param organizationIds at most a page of ids; the caller bounds it
     * @param featureKeys     the keys to decide; the answers name only these
     * @return every requested id mapped to the requested keys that are off for it
     */
    public Map<Long, Set<String>> disabledFeatureKeysFor(Collection<Long> organizationIds,
                                                         Collection<String> featureKeys) {
        Map<Long, Set<String>> off = new HashMap<>();
        organizationIds.forEach(id -> off.put(id, new TreeSet<>()));
        if (organizationIds.isEmpty()) {
            return Map.of();
        }
        for (String featureKey : new LinkedHashSet<>(featureKeys)) {
            resolver.resolveForOrganizations(featureKey, organizationIds).forEach((organizationId, enabled) -> {
                if (!enabled && off.containsKey(organizationId)) {
                    off.get(organizationId).add(featureKey);
                }
            });
        }
        Map<Long, Set<String>> answers = new HashMap<>();
        off.forEach((organizationId, keys) -> answers.put(organizationId, Set.copyOf(keys)));
        return Map.copyOf(answers);
    }

    private static ResolvedFlag resolveForOrg(GlobalFeatureFlag g, Long orgId, String orgType,
                                              OrganizationFeatureFlag orgOverride, OrgTypeFeatureFlag typeOverride) {
        Boolean orgTypeEnabled = typeOverride != null ? typeOverride.getEnabled() : null;
        FeatureFlagDecision.Outcome outcome = FeatureFlagDecision.decide(
                toRow(g), orgId, orgType, toOverride(orgOverride), orgTypeEnabled);
        if (!outcome.orgOverridable()) {
            return new ResolvedFlag(g, null, null, orgType, outcome.effectiveEnabled(), false, false);
        }
        return new ResolvedFlag(g, orgOverride != null ? orgOverride.getEnabled() : null, orgTypeEnabled, orgType,
                outcome.effectiveEnabled(), outcome.orgControllable(), isAdminLocked(orgOverride));
    }

    /** Names, on each flag that is on, the required flag that is off and so pauses its automatic work. */
    private static List<ResolvedFlag> withAutomaticWorkPausedBy(List<ResolvedFlag> flags) {
        Map<String, Boolean> effective = flags.stream()
                .collect(Collectors.toMap(f -> f.global().getFeatureKey(), ResolvedFlag::effectiveEnabled));
        return flags.stream().map(flag -> {
            String required = FeatureFlags.AUTOMATIC_WORK_REQUIRES.get(flag.global().getFeatureKey());
            boolean paused = required != null && flag.effectiveEnabled()
                    && Boolean.FALSE.equals(effective.get(required));
            return paused ? flag.withAutomaticWorkPausedBy(required) : flag;
        }).toList();
    }

    /** The decision for one flag and org from already-loaded rows; used by the write guards. */
    private FeatureFlagDecision.Outcome decide(GlobalFeatureFlag g, Long orgId, String orgType,
                                               OrganizationFeatureFlag orgOverride, OrgTypeFeatureFlag typeOverride) {
        return FeatureFlagDecision.decide(toRow(g), orgId, orgType,
                toOverride(orgOverride), typeOverride != null ? typeOverride.getEnabled() : null);
    }

    private static FeatureFlagDecision.GlobalRow toRow(GlobalFeatureFlag g) {
        return new FeatureFlagDecision.GlobalRow(
                g.getFeatureKey(), Boolean.TRUE.equals(g.getEnabled()), g.getScope(), g.getCategory());
    }

    private static FeatureFlagDecision.OrgOverride toOverride(OrganizationFeatureFlag orgOverride) {
        return orgOverride == null ? null : new FeatureFlagDecision.OrgOverride(
                Boolean.TRUE.equals(orgOverride.getEnabled()), isAdminLocked(orgOverride));
    }

    private static boolean isAdminLocked(OrganizationFeatureFlag orgOverride) {
        return orgOverride != null && Boolean.TRUE.equals(orgOverride.getAdminLocked());
    }

    private static OverrideState stateOf(OrganizationFeatureFlag orgOverride) {
        return new OverrideState(Boolean.TRUE.equals(orgOverride.getEnabled()), isAdminLocked(orgOverride));
    }

    /** Returns all org-type overrides for a given org type. */
    public List<OrgTypeFeatureFlag> listOrgTypeEffective(String orgType) {
        return orgTypeRepo.findAllByOrgType(orgType);
    }

    /** Returns all org overrides for a given feature key (paginated, for admin view). */
    public Page<OrganizationFeatureFlag> listOrgOverrides(String featureKey, Pageable pageable) {
        return orgRepo.findAllByFeatureKey(featureKey, pageable);
    }

    // ── Write (global) ───────────────────────────────────────────────────

    /**
     * Updates the global enabled state of a feature flag, audited with the operator's reason.
     *
     * @param reason the operator's note; persisted in the audit row (trimmed, capped), may be null
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public GlobalFeatureFlag updateGlobal(String featureKey, boolean enabled, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        GlobalFeatureFlag flag = getGlobal(featureKey);
        Integer actorId = GatewayRequestContext.getUserId();
        boolean before = Boolean.TRUE.equals(flag.getEnabled());
        log.info("Global feature flag '{}' set to {} by userId={}", featureKey, enabled, actorId);
        flag.setEnabled(enabled);
        flag.setUpdatedByUserId(actorId);
        GlobalFeatureFlag saved = globalRepo.save(flag);
        changeAudit.recordGlobal(saved.getId(), featureKey, before, enabled, reason);
        if (before != enabled) {
            forcedChangesProvider.getObject().recordGlobal(featureKey, before, enabled, actorId);
        }
        return saved;
    }

    // ── Write (org-type-level) ────────────────────────────────────────────

    /**
     * Sets or updates an org-type-level default for a feature flag.
     * Affects all organizations of the given type that have no org-specific override.
     *
     * @param reason the operator's note for the audit row, may be null
     * @throws BadRequestException if the global flag is disabled or scope is not ORG
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public OrgTypeFeatureFlag upsertOrgTypeOverride(String orgType, String featureKey, boolean enabled, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        assertValidOrgType(orgType);
        GlobalFeatureFlag global = getGlobal(featureKey);

        if (!SCOPE_ORG.equals(global.getScope())) {
            throw new BadRequestException(
                    "Feature flag '" + featureKey + "' is not org-scoped and cannot be overridden at the org-type level.");
        }
        if (!Boolean.TRUE.equals(global.getEnabled())) {
            throw new BadRequestException(
                    "Feature flag '" + featureKey + "' is globally disabled and cannot be overridden.");
        }
        Integer actorId = GatewayRequestContext.getUserId();
        Optional<OrgTypeFeatureFlag> existing = orgTypeRepo.findByOrgTypeAndFeatureKey(orgType, featureKey);
        Boolean before = existing.map(OrgTypeFeatureFlag::getEnabled).orElse(null);

        OrgTypeFeatureFlag flag = existing.orElseGet(() -> OrgTypeFeatureFlag.builder()
                .orgType(orgType)
                .featureKey(featureKey)
                .build());
        flag.setEnabled(enabled);
        flag.setUpdatedByUserId(actorId);
        log.info("Org-type feature flag '{}' {} as {} for orgType={} by userId={}",
                featureKey, existing.isPresent() ? "updated" : "created", enabled, orgType, actorId);
        OrgTypeFeatureFlag saved = orgTypeRepo.save(flag);
        if (!Boolean.valueOf(enabled).equals(before)) {
            changeAudit.recordOrgType(saved.getId(), orgType, featureKey, before, enabled, reason);
            forcedChangesProvider.getObject().recordOrgType(featureKey, orgType, before, enabled, actorId);
        }
        return saved;
    }

    /**
     * Removes an org-type-level override, reverting that org type to the global default.
     *
     * @param reason the operator's note for the audit row, may be null
     * @return {@code true} if an override was found and removed
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public boolean removeOrgTypeOverride(String orgType, String featureKey, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        assertValidOrgType(orgType);
        Optional<OrgTypeFeatureFlag> existing = orgTypeRepo.findByOrgTypeAndFeatureKey(orgType, featureKey);
        if (existing.isEmpty()) {
            return false;
        }
        int deleted = orgTypeRepo.deleteByOrgTypeAndFeatureKey(orgType, featureKey);
        if (deleted > 0) {
            log.info("Org-type feature flag override '{}' removed for orgType={} by userId={}",
                    featureKey, orgType, GatewayRequestContext.getUserId());
            changeAudit.recordOrgType(existing.get().getId(), orgType, featureKey,
                    existing.get().getEnabled(), null, reason);
            forcedChangesProvider.getObject().recordOrgType(featureKey, orgType, existing.get().getEnabled(), null,
                    GatewayRequestContext.getUserId());
        }
        return deleted > 0;
    }

    /**
     * Bulk-sets an org-type override for every globally-enabled ORG-scope flag.
     * Globally-disabled flags are silently skipped.
     * Each flag that changes gets its own audit row carrying {@code reason}. Flags are written in
     * sorted key order: each forced change locks its feature until commit, and a fixed order keeps two
     * concurrent bulk writes from deadlocking.
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public List<OrgTypeFeatureFlag> bulkSetOrgTypeOverrides(String orgType, boolean enabled, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        assertValidOrgType(orgType);
        return listGlobal().stream()
                .filter(g -> SCOPE_ORG.equals(g.getScope())
                        && Boolean.TRUE.equals(g.getEnabled()))
                .sorted(Comparator.comparing(GlobalFeatureFlag::getFeatureKey))
                .map(g -> upsertOrgTypeOverride(orgType, g.getFeatureKey(), enabled, reason))
                .toList();
    }

    // ── Write (org-level) ────────────────────────────────────────────────

    /**
     * Sets or updates the org admin's override for a feature flag.
     *
     * @param reason the org admin's note for the audit row, may be null
     * @throws BadRequestException if the org admin cannot control this flag for the org
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public OrganizationFeatureFlag upsertOrgOverride(Long orgId, String featureKey, boolean enabled, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        GlobalFeatureFlag global = getGlobal(featureKey);
        String orgType = resolveOrgType(orgId);
        Optional<OrganizationFeatureFlag> existing = orgRepo.findByOrganizationIdAndFeatureKey(orgId, featureKey);
        OrgTypeFeatureFlag typeOverride = orgType == null ? null
                : orgTypeRepo.findByOrgTypeAndFeatureKey(orgType, featureKey).orElse(null);

        FeatureFlagDecision.Outcome current = decide(global, orgId, orgType, existing.orElse(null), typeOverride);
        if (!current.orgControllable()) {
            throw new BadRequestException("Feature flag '" + featureKey + "' cannot be overridden for this "
                    + "organization: it is not org-scoped, is off globally, or is decided by a platform "
                    + "administrator.");
        }
        if (!enabled && current.effectiveEnabled()) {
            // Clear-first: refused with 409 while anything still runs; the lock it takes
            // holds every create path of the feature until this switch-off commits.
            lifecycleServiceProvider.getObject().lockAndAssertNothingInUse(orgId, featureKey);
        }
        return saveOrgOverride(orgId, featureKey, enabled, false, existing, reason);
    }

    /**
     * Super admin: sets or updates an org override for any organization. The override is admin-locked,
     * so it outranks the org-type default and the org admin can neither change nor remove it.
     *
     * @param reason the super admin's note for the audit row, may be null
     * @throws BadRequestException if an org override cannot decide this flag for the org, or the write would
     *                             switch it on while the flag its automatic work requires is off
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public OrganizationFeatureFlag upsertOrgOverrideAsAdmin(Long orgId, String featureKey, boolean enabled,
                                                            String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        GlobalFeatureFlag global = getGlobal(featureKey);

        if (!decide(global, orgId, resolveOrgType(orgId), null, null).orgOverridable()) {
            throw new BadRequestException("Feature flag '" + featureKey + "' cannot be overridden for this "
                    + "organization: it is not org-scoped or is off globally.");
        }
        refuseSwitchOnWhileRequirementOff(featureKey, orgId,
                () -> enabled && !resolver.resolveUncached(featureKey, orgId));
        return saveOrgOverride(orgId, featureKey, enabled, true,
                orgRepo.findByOrganizationIdAndFeatureKey(orgId, featureKey), reason);
    }

    private OrganizationFeatureFlag saveOrgOverride(Long orgId, String featureKey, boolean enabled,
                                                    boolean adminLocked, Optional<OrganizationFeatureFlag> existing,
                                                    String reason) {
        Integer actorId = GatewayRequestContext.getUserId();
        OverrideState before = existing.map(FeatureFlagService::stateOf).orElse(null);
        // A soft-deleted row for this org and key is restored rather than a new one inserted: the
        // unique index on (organization_id, feature_key) is partial (is_deleted = false).
        OrganizationFeatureFlag flag = existing
                .or(() -> orgRepo.findByOrganizationIdAndFeatureKeyIncludeDeleted(orgId, featureKey))
                .orElseGet(() -> OrganizationFeatureFlag.builder()
                        .organizationId(orgId)
                        .featureKey(featureKey)
                        .build());
        flag.setIsDeleted(false);
        flag.setEnabled(enabled);
        flag.setAdminLocked(adminLocked);
        flag.setUpdatedByUserId(actorId);
        log.info("Org feature flag '{}' set to {} (adminLocked={}) for orgId={} by userId={}",
                featureKey, enabled, adminLocked, orgId, actorId);
        OrganizationFeatureFlag saved = orgRepo.save(flag);
        OverrideState after = new OverrideState(enabled, adminLocked);
        if (!after.equals(before)) {
            changeAudit.recordOrganization(saved.getId(), orgId, featureKey, before, after, reason);
            if (adminLocked) {
                forcedChangesProvider.getObject().recordOrganization(featureKey, orgId, before, after, actorId);
            } else {
                publishStateChanged(featureKey, orgId);
            }
        }
        return saved;
    }

    /**
     * Removes the org admin's override, reverting the org to the org-type default or global default.
     * A removal that would switch the feature off goes through the same clear-first guard as
     * {@link #upsertOrgOverride}.
     *
     * @param reason the org admin's note for the audit row, may be null
     * @return {@code true} if an override was found and removed
     * @throws BadRequestException   if the override was set by a super admin
     * @throws com.certmanagement.exception.FeatureInUseException (409) if the removal would switch the
     *                                                             feature off while it is in use
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public boolean removeOrgOverride(Long orgId, String featureKey, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        Optional<OrganizationFeatureFlag> existing = orgRepo.findByOrganizationIdAndFeatureKey(orgId, featureKey);
        if (existing.isEmpty()) {
            return false;
        }
        if (isAdminLocked(existing.get())) {
            throw new BadRequestException("Feature flag '" + featureKey + "' was set for this organization by a "
                    + "platform administrator and only a platform administrator can remove it.");
        }
        if (removalSwitchesOff(orgId, featureKey, existing.get())) {
            // Clear-first, as in upsertOrgOverride: 409 while anything still runs, and the
            // lock holds every create path of the feature until this removal commits.
            lifecycleServiceProvider.getObject().lockAndAssertNothingInUse(orgId, featureKey);
        }
        // The conditional delete still guards against a super admin locking the row concurrently.
        int deleted = orgRepo.softDeleteUnlockedByOrganizationIdAndFeatureKey(orgId, featureKey);
        if (deleted > 0) {
            log.info("Org feature flag override '{}' removed for orgId={} by userId={}",
                    featureKey, orgId, GatewayRequestContext.getUserId());
            changeAudit.recordOrganization(existing.get().getId(), orgId, featureKey,
                    stateOf(existing.get()), null, reason);
            publishStateChanged(featureKey, orgId);
        }
        return deleted > 0;
    }

    /**
     * Whether removing {@code override} takes the org's effective state from on to off. Under
     * today's precedence it never does (an unlocked override sits either above a default that is on
     * or below an org-type "off" that already wins), so the guard it drives is defensive: removal can
     * never become a guard-free switch-off if the precedence changes. Package-private for that test.
     */
    boolean removalSwitchesOff(Long orgId, String featureKey, OrganizationFeatureFlag override) {
        GlobalFeatureFlag global = getGlobal(featureKey);
        String orgType = resolveOrgType(orgId);
        OrgTypeFeatureFlag typeOverride = orgType == null ? null
                : orgTypeRepo.findByOrgTypeAndFeatureKey(orgType, featureKey).orElse(null);
        return decide(global, orgId, orgType, override, typeOverride).effectiveEnabled()
                && !decide(global, orgId, orgType, null, typeOverride).effectiveEnabled();
    }

    private boolean removalSwitchesOn(Long orgId, String featureKey) {
        GlobalFeatureFlag global = getGlobal(featureKey);
        String orgType = resolveOrgType(orgId);
        OrgTypeFeatureFlag typeOverride = orgType == null ? null
                : orgTypeRepo.findByOrgTypeAndFeatureKey(orgType, featureKey).orElse(null);
        return !resolver.resolveUncached(featureKey, orgId)
                && decide(global, orgId, orgType, null, typeOverride).effectiveEnabled();
    }

    /**
     * Refuses a super admin's change that would switch {@code featureKey} on for the organization while the
     * flag its automatic work requires is off ({@link FeatureFlags#AUTOMATIC_WORK_REQUIRES}).
     *
     * @throws BadRequestException naming both flags
     */
    private void refuseSwitchOnWhileRequirementOff(String featureKey, Long orgId, BooleanSupplier switchesOn) {
        String requiredKey = FeatureFlags.AUTOMATIC_WORK_REQUIRES.get(featureKey);
        if (requiredKey == null || resolver.resolveUncached(requiredKey, orgId) || !switchesOn.getAsBoolean()) {
            return;
        }
        String required = getGlobal(requiredKey).getDisplayName();
        throw new BadRequestException(getGlobal(featureKey).getDisplayName() + " can't be turned on while " + required
                + " is off for this organization. Turn " + required + " on first.");
    }

    /**
     * Super admin: removes an org override for any org, admin-locked or not.
     *
     * @param reason the super admin's note for the audit row, may be null
     * @throws BadRequestException if the removal would switch the feature on while the flag its automatic
     *                             work requires is off
     */
    @Transactional
    @CacheEvict(cacheNames = FEATURE_FLAGS, allEntries = true)
    public boolean removeOrgOverrideAsAdmin(Long orgId, String featureKey, String reason) {
        events.publishEvent(new FeatureFlagsChangedEvent());
        Optional<OrganizationFeatureFlag> existing = orgRepo.findByOrganizationIdAndFeatureKey(orgId, featureKey);
        if (existing.isEmpty()) {
            return false;
        }
        refuseSwitchOnWhileRequirementOff(featureKey, orgId, () -> removalSwitchesOn(orgId, featureKey));
        int deleted = orgRepo.softDeleteByOrganizationIdAndFeatureKey(orgId, featureKey);
        if (deleted > 0) {
            log.info("Org feature flag override '{}' removed by super admin for orgId={} by userId={}",
                    featureKey, orgId, GatewayRequestContext.getUserId());
            changeAudit.recordOrganization(existing.get().getId(), orgId, featureKey,
                    stateOf(existing.get()), null, reason);
            forcedChangesProvider.getObject().recordOrganization(featureKey, orgId, stateOf(existing.get()), null,
                    GatewayRequestContext.getUserId());
        }
        return deleted > 0;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * An organization admin's own change: lets the feature lifecycle reconcile that organization after
     * commit (resume PLATFORM-paused records when the feature came back on). Never forced: the
     * switch-off went through clear-first, so nothing of the feature is left running. A super admin's
     * change is recorded as a forced transition through {@link ForcedFlagChanges} instead.
     */
    private void publishStateChanged(String featureKey, Long orgId) {
        events.publishEvent(new FeatureFlagStateChangedEvent(featureKey, orgId, GatewayRequestContext.getUserId(),
                null));
    }

    private String resolveOrgType(Long orgId) {
        if (orgId == null) return null;
        return organizationRepo.findOrgTypeById(orgId).orElse(null);
    }

    // ── Value types ───────────────────────────────────────────────────────

    /**
     * A global flag resolved for one organization. {@code orgControllable} is true when the org admin
     * may set it: an ORG-scope flag that is on globally and not decided by a super admin.
     * {@code adminLocked} is true when a super admin set this organization's override.
     * {@code automaticWorkPausedBy} names the required flag that is off while this
     * one is on, so its automatic work is paused ({@link FeatureFlags#AUTOMATIC_WORK_REQUIRES}); else null.
     */
    public record ResolvedFlag(
            GlobalFeatureFlag global,
            Boolean orgEnabled,
            Boolean orgTypeEnabled,
            String orgType,
            boolean effectiveEnabled,
            boolean orgControllable,
            boolean adminLocked,
            String automaticWorkPausedBy) {

        /** A flag whose automatic work nothing pauses. */
        public ResolvedFlag(GlobalFeatureFlag global, Boolean orgEnabled, Boolean orgTypeEnabled, String orgType,
                            boolean effectiveEnabled, boolean orgControllable, boolean adminLocked) {
            this(global, orgEnabled, orgTypeEnabled, orgType, effectiveEnabled, orgControllable, adminLocked, null);
        }

        ResolvedFlag withAutomaticWorkPausedBy(String requiredFeatureKey) {
            return new ResolvedFlag(global, orgEnabled, orgTypeEnabled, orgType, effectiveEnabled, orgControllable,
                    adminLocked, requiredFeatureKey);
        }
    }
}
