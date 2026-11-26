// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.repository.GlobalFeatureFlagRepository;
import com.certmanagement.repository.OrgTypeFeatureFlagRepository;
import com.certmanagement.repository.OrganizationFeatureFlagRepository;
import com.certmanagement.repository.OrganizationRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static com.certmanagement.config.CacheConfig.FEATURE_FLAGS;

/**
 * Resolves whether a flag is enabled for an organization; {@link FeatureFlagService} documents the
 * precedence rules and {@link FeatureFlagDecision} applies them. Decisions are cached per flag and
 * organization ({@code orgId == null} is the platform-level check crons and listeners make), and per
 * organization for the whole catalog ({@link #effectiveMap}); {@link FeatureFlagService} evicts on
 * every write.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class FeatureFlagResolver {

    private final GlobalFeatureFlagRepository globalRepo;
    private final OrganizationFeatureFlagRepository orgRepo;
    private final OrgTypeFeatureFlagRepository orgTypeRepo;
    private final OrganizationRepository organizationRepo;

    @Cacheable(cacheNames = FEATURE_FLAGS, key = "#featureKey + ':' + (#orgId ?: 'platform')")
    public boolean resolve(String featureKey, Long orgId) {
        boolean enabled = resolveFromDatabase(featureKey, orgId);
        log.debug("Feature flag '{}' resolved for orgId={} (cache miss): enabled={}", featureKey, orgId, enabled);
        return enabled;
    }

    /**
     * Every flag's answer for one organization, keyed by feature key, from four queries however many
     * flags there are (the global catalog, the organization's type, its overrides, its org-type
     * defaults), each decided by {@link FeatureFlagDecision} like {@link #resolve}. Cached in the
     * same cache as the single-flag answers, so every flag write ({@code @CacheEvict(allEntries)})
     * and every cross-pod change ({@link SharedFeatureFlags} clears the whole cache) drops it.
     *
     * @param orgId the organization; required
     * @return an immutable map, sorted by feature key
     */
    @Cacheable(cacheNames = FEATURE_FLAGS, key = "'effective:' + #orgId")
    public Map<String, Boolean> effectiveMap(Long orgId) {
        Objects.requireNonNull(orgId, "orgId");
        String orgType = organizationRepo.findOrgTypeById(orgId).orElse(null);
        Map<String, FeatureFlagDecision.OrgOverride> overrides = orgRepo.findAllByOrganizationId(orgId).stream()
                .collect(Collectors.toMap(OrganizationFeatureFlag::getFeatureKey,
                        o -> new FeatureFlagDecision.OrgOverride(Boolean.TRUE.equals(o.getEnabled()),
                                Boolean.TRUE.equals(o.getAdminLocked())), (first, second) -> first));
        Map<String, Boolean> typeDefaults = orgType == null ? Map.of() : orgTypeRepo.findAllByOrgType(orgType).stream()
                .collect(Collectors.toMap(OrgTypeFeatureFlag::getFeatureKey, t -> Boolean.TRUE.equals(t.getEnabled()),
                        (first, second) -> first));
        Map<String, Boolean> answers = new TreeMap<>();
        for (GlobalFeatureFlag flag : globalRepo.findAll()) {
            FeatureFlagDecision.GlobalRow global = new FeatureFlagDecision.GlobalRow(flag.getFeatureKey(),
                    Boolean.TRUE.equals(flag.getEnabled()), flag.getScope(), flag.getCategory());
            answers.put(flag.getFeatureKey(), FeatureFlagDecision.decide(global, orgId, orgType,
                    overrides.get(flag.getFeatureKey()), typeDefaults.get(flag.getFeatureKey())).effectiveEnabled());
        }
        return Collections.unmodifiableMap(answers);
    }
    /** The answer from the database, bypassing the cache; for checks that must see the latest row. */
    public boolean resolveUncached(String featureKey, Long orgId) {
        return resolveFromDatabase(featureKey, orgId);
    }

    /**
     * One flag's own answer for a page of organizations: four queries however many there are, decided
     * by {@link FeatureFlagDecision} like {@link #resolve}. Uncached: for batch reads that visit each
     * organization once, where a per-organization cache miss would cost four queries each.
     *
     * @param organizationIds at most a page of ids; the caller bounds it
     * @return every requested id mapped to whether the flag is on for it
     */
    public Map<Long, Boolean> resolveForOrganizations(String featureKey, Collection<Long> organizationIds) {
        if (organizationIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, Boolean> answers = new HashMap<>();
        loadOwnInputs(featureKey, organizationIds).forEach((organizationId, inputs) ->
                answers.put(organizationId, inputs.enabled()));
        return answers;
    }

    /**
     * Every row the decision reads for one flag and a page of organizations, uncached: the global row,
     * the organizations' types, their overrides of this flag and the org-type defaults (four queries),
     * and the same for the flag its automatic work requires, if any (four more).
     *
     * @param organizationIds at most a page of ids; the caller bounds it
     * @return the inputs of every requested id
     */
    public Map<Long, FeatureFlagInputs> loadInputs(String featureKey, Collection<Long> organizationIds) {
        if (organizationIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, FeatureFlagInputs> inputs = loadOwnInputs(featureKey, organizationIds);
        String requiredKey = FeatureFlags.AUTOMATIC_WORK_REQUIRES.get(featureKey);
        if (requiredKey == null) {
            return inputs;
        }
        Map<Long, FeatureFlagInputs> requirements = loadOwnInputs(requiredKey, organizationIds);
        Map<Long, FeatureFlagInputs> combined = new HashMap<>();
        inputs.forEach((organizationId, own) ->
                combined.put(organizationId, own.withRequirement(requirements.get(organizationId))));
        return combined;
    }

    /**
     * {@link #loadInputs} for one organization, uncached and complete (every layer is loaded, even
     * when the current answer does not need it, so a layer can be rolled back).
     */
    public FeatureFlagInputs loadInputsUncached(String featureKey, long organizationId) {
        FeatureFlagInputs own = loadOwnInputsUncached(featureKey, organizationId);
        String requiredKey = FeatureFlags.AUTOMATIC_WORK_REQUIRES.get(featureKey);
        return requiredKey == null ? own : own.withRequirement(loadOwnInputsUncached(requiredKey, organizationId));
    }

    /**
     * The flag that stops {@code featureKey}'s automatic work for the organization, read past the cache:
     * the feature itself when it is off, else the flag its automatic work requires when that is off.
     *
     * @return the stopping flag's key, or empty when the automatic work may run
     */
    public Optional<String> automaticWorkBlockerUncached(String featureKey, Long orgId) {
        if (!resolveUncached(featureKey, orgId)) {
            return Optional.of(featureKey);
        }
        String requiredKey = FeatureFlags.AUTOMATIC_WORK_REQUIRES.get(featureKey);
        boolean requirementOff = requiredKey != null && !resolveUncached(requiredKey, orgId);
        return requirementOff ? Optional.of(requiredKey) : Optional.empty();
    }

    private Map<Long, FeatureFlagInputs> loadOwnInputs(String featureKey, Collection<Long> organizationIds) {
        FeatureFlagDecision.GlobalRow global = globalRow(featureKey).orElse(null);
        Map<Long, String> orgTypes = organizationRepo.findOrgTypesByIdIn(organizationIds).stream()
                .filter(row -> row.getOrgType() != null)
                .collect(Collectors.toMap(OrganizationRepository.OrgTypeView::getId,
                        OrganizationRepository.OrgTypeView::getOrgType));
        Map<Long, FeatureFlagDecision.OrgOverride> overrides = orgRepo
                .findAllByFeatureKeyAndOrganizationIdIn(featureKey, organizationIds).stream()
                .collect(Collectors.toMap(OrganizationFeatureFlag::getOrganizationId,
                        o -> new FeatureFlagDecision.OrgOverride(Boolean.TRUE.equals(o.getEnabled()),
                                Boolean.TRUE.equals(o.getAdminLocked())), (first, second) -> first));
        Map<String, Boolean> typeDefaults = orgTypeRepo.findAllByFeatureKey(featureKey).stream()
                .collect(Collectors.toMap(OrgTypeFeatureFlag::getOrgType, t -> Boolean.TRUE.equals(t.getEnabled()),
                        (first, second) -> first));
        Map<Long, FeatureFlagInputs> inputs = new HashMap<>();
        for (Long organizationId : organizationIds) {
            String orgType = orgTypes.get(organizationId);
            inputs.put(organizationId, new FeatureFlagInputs(featureKey, global, organizationId,
                    orgType, overrides.get(organizationId), orgType == null ? null : typeDefaults.get(orgType),
                    null));
        }
        return inputs;
    }

    private FeatureFlagInputs loadOwnInputsUncached(String featureKey, long organizationId) {
        FeatureFlagDecision.GlobalRow global = globalRow(featureKey).orElse(null);
        String orgType = organizationRepo.findOrgTypeById(organizationId).orElse(null);
        FeatureFlagDecision.OrgOverride orgOverride = orgRepo
                .findOverrideViewByOrganizationIdAndFeatureKey(organizationId, featureKey)
                .map(o -> new FeatureFlagDecision.OrgOverride(
                        Boolean.TRUE.equals(o.getEnabled()), Boolean.TRUE.equals(o.getAdminLocked())))
                .orElse(null);
        Boolean orgTypeEnabled = orgType == null ? null : orgTypeRepo
                .findEnabledByOrgTypeAndFeatureKey(orgType, featureKey)
                .map(OrgTypeFeatureFlagRepository.EnabledView::getEnabled)
                .orElse(null);
        return new FeatureFlagInputs(featureKey, global, organizationId, orgType,
                orgOverride, orgTypeEnabled, null);
    }

    private Optional<FeatureFlagDecision.GlobalRow> globalRow(String featureKey) {
        return globalRepo.findResolutionViewByFeatureKey(featureKey)
                .map(view -> new FeatureFlagDecision.GlobalRow(
                        featureKey, Boolean.TRUE.equals(view.getEnabled()), view.getScope(), view.getCategory()));
    }

    /**
     * Loads only the rows the decision can need, then hands them to {@link FeatureFlagDecision}:
     * the global row always; the org type, the org override and the org-type default only when an
     * org override could decide the flag.
     */
    private boolean resolveFromDatabase(String featureKey, Long orgId) {
        Optional<GlobalFeatureFlagRepository.ResolutionView> globalOpt = globalRepo.findResolutionViewByFeatureKey(featureKey);
        if (globalOpt.isEmpty()) {
            log.warn("Feature flag '{}' not found in global_feature_flags — defaulting to enabled", featureKey);
            return true;
        }
        GlobalFeatureFlagRepository.ResolutionView view = globalOpt.get();
        FeatureFlagDecision.GlobalRow global = new FeatureFlagDecision.GlobalRow(
                featureKey, Boolean.TRUE.equals(view.getEnabled()), view.getScope(), view.getCategory());
        if (!FeatureFlagDecision.needsOrgRows(global, orgId)) {
            return FeatureFlagDecision.decide(global, orgId, null, null, null).effectiveEnabled();
        }

        String orgType = organizationRepo.findOrgTypeById(orgId).orElse(null);
        FeatureFlagDecision.OrgOverride orgOverride = orgRepo
                .findOverrideViewByOrganizationIdAndFeatureKey(orgId, featureKey)
                .map(o -> new FeatureFlagDecision.OrgOverride(
                        Boolean.TRUE.equals(o.getEnabled()), Boolean.TRUE.equals(o.getAdminLocked())))
                .orElse(null);
        Boolean orgTypeEnabled = orgType == null ? null : orgTypeRepo
                .findEnabledByOrgTypeAndFeatureKey(orgType, featureKey)
                .map(OrgTypeFeatureFlagRepository.EnabledView::getEnabled)
                .orElse(null);
        return FeatureFlagDecision.decide(global, orgId, orgType, orgOverride, orgTypeEnabled)
                .effectiveEnabled();
    }
}
