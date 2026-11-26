// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.featureflags.FeatureFlagDto;
import com.certmanagement.dto.featureflags.FeatureFlagSummaryDto;
import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.GlobalFeatureFlag;
import com.certmanagement.entity.OrgTypeFeatureFlag;
import com.certmanagement.entity.Organization;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.dto.featureflags.FeatureImpactResponse;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.repository.lifecycle.ImpactScope;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.lifecycle.FeatureImpactService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * Super-admin feature flag endpoints — global, org-type, and per-org management.
 *
 * <p>Every endpoint is for SUPER_ADMIN only, checked by role on the class so that an endpoint added
 * later cannot miss it. These endpoints act on every organization at once, or on any organization
 * by id.
 *
 * <p>Path ordering: {@code /summary} and {@code /org-type/*} are declared before
 * {@code /{featureKey}} to prevent Spring MVC from treating literal segments as path variables.
 */
@RestController
@RequiredArgsConstructor
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
@Tag(name = "Admin Feature Flags", description = "Super-admin global and org-type feature flag management")
public class AdminFeatureFlagController {

    private final FeatureFlagService     featureFlagService;
    private final OrganizationRepository organizationRepository;
    private final FeatureImpactService   featureImpactService;

    // ── GET /api/v1/admin/feature-flags/org/{organizationId} ─────────────

    @GetMapping(Paths.ADMIN_FF_ORG_FLAGS)
    @Operation(
            summary = "List effective flags for a specific organization",
            description = "Returns all ORG-scope feature flags with their effective state for the given organization, " +
                          "including org-type and org-specific overrides. Allows a super admin to view any org's flag state.")
    public ResponseEntity<Map<String, Object>> listFlagsForOrg(@PathVariable Long organizationId) {
        List<FeatureFlagDto> flags = featureFlagService.listEffective(organizationId)
                .stream()
                .filter(r -> "ORG".equals(r.global().getScope()))
                .map(FeatureFlagDto::from)
                .toList();
        Map<String, Boolean> effectiveMap = flags.stream()
                .collect(Collectors.toMap(FeatureFlagDto::getFeatureKey, FeatureFlagDto::isEffectiveEnabled));
        return ResponseEntity.ok(Map.of("flags", flags, "effectiveMap", effectiveMap));
    }

    // ── GET /api/v1/admin/feature-flags/summary ──────────────────────────

    @GetMapping(Paths.ADMIN_FF_SUMMARY)
    @Operation(
            summary = "Flags × orgs matrix",
            description = "Returns every flag's effective state for every active organization, " +
                          "including org type and org-type-level overrides.")
    public ResponseEntity<List<FeatureFlagSummaryDto>> summary() {
        // Unbounded by design: the matrix covers every active organization (pre-existing contract).
        // The flags are resolved in batch, not one listEffective round per organization.
        List<Organization> orgs    = organizationRepository.findByActiveTrue();
        List<GlobalFeatureFlag> globals = featureFlagService.listGlobal();
        Map<Long, String> orgTypeById = new java.util.LinkedHashMap<>();
        orgs.forEach(org -> orgTypeById.put(org.getId(), org.getOrgType()));
        Map<Long, List<FeatureFlagService.ResolvedFlag>> resolvedByOrg =
                featureFlagService.listEffectiveForOrganizations(orgTypeById);
        List<FeatureFlagSummaryDto> result = new ArrayList<>();

        for (Organization org : orgs) {
            Map<String, FeatureFlagService.ResolvedFlag> resolvedByKey = resolvedByOrg
                    .getOrDefault(org.getId(), List.of()).stream()
                    .collect(Collectors.toMap(r -> r.global().getFeatureKey(), r -> r));

            for (GlobalFeatureFlag g : globals) {
                FeatureFlagService.ResolvedFlag r = resolvedByKey.get(g.getFeatureKey());
                result.add(FeatureFlagSummaryDto.builder()
                        .organizationId(org.getId())
                        .organizationName(org.getName())
                        .orgType(org.getOrgType())
                        .featureKey(g.getFeatureKey())
                        .category(g.getCategory())
                        .globalEnabled(Boolean.TRUE.equals(g.getEnabled()))
                        .orgTypeEnabled(r != null ? r.orgTypeEnabled() : null)
                        .orgEnabled(r != null ? r.orgEnabled() : null)
                        .effectiveEnabled(r != null ? r.effectiveEnabled() : Boolean.TRUE.equals(g.getEnabled()))
                        .build());
            }
        }
        return ResponseEntity.ok(result);
    }

    // ── GET /api/v1/admin/feature-flags/{featureKey}/impact ──────────────

    @GetMapping(Paths.ADMIN_FF_IMPACT)
    @Operation(
            summary = "Preview what switching a feature off would affect",
            description = "Counts the records that would be paused or stop working, the organizations holding " +
                          "them, whether their admins are emailed, and warnings such as " +
                          "certificates expiring within 30 days. Platform-wide, for one organization " +
                          "(organizationId), or for one organization type (orgType=B2B, for an org-type " +
                          "default); the two filters are mutually exclusive (400). Aggregate queries only. " +
                          "organizationsAffected counts each organization once across every kind. " +
                          "404 for an unknown feature or organization.")
    public ResponseEntity<FeatureImpactResponse> impact(@PathVariable String featureKey,
                                                        @RequestParam(required = false) Long organizationId,
                                                        @RequestParam(required = false) String orgType) {
        ImpactScope scope;
        try {
            scope = new ImpactScope(organizationId, orgType);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(e.getMessage());
        }
        featureFlagService.getGlobal(featureKey);
        if (organizationId != null && !organizationRepository.existsLiveById(organizationId)) {
            throw new ResourceNotFoundException("Organization not found: " + organizationId);
        }
        return ResponseEntity.ok(featureImpactService.impact(featureKey, scope));
    }

    // ── GET /api/v1/admin/feature-flags/org-type/{orgType} ───────────────

    @GetMapping(Paths.ADMIN_FF_ORG_TYPE_BASE)
    @Operation(
            summary = "List org-type overrides",
            description = "Returns all flag overrides set for the given org type (B2B).")
    public ResponseEntity<List<OrgTypeFeatureFlag>> listOrgTypeOverrides(@PathVariable String orgType) {
        return ResponseEntity.ok(featureFlagService.listOrgTypeEffective(orgType));
    }

    // ── GET /api/v1/admin/feature-flags ──────────────────────────────────

    @GetMapping(Paths.ADMIN_FF_BASE)
    @Operation(summary = "List all global feature flags")
    public ResponseEntity<List<GlobalFeatureFlag>> listGlobal() {
        return ResponseEntity.ok(featureFlagService.listGlobal());
    }

    // ── PUT /api/v1/admin/feature-flags/{featureKey} ──────────────────────

    @AuditFailure(value = AuditEventType.FEATURE_CHANGED, target = "#featureKey", name = "#featureKey")
    @PutMapping(Paths.ADMIN_FF_KEY)
    @Operation(
            summary = "Enable or disable a global feature flag",
            description = "When a global flag is disabled, it overrides all org-type and org-level settings.")
    public ResponseEntity<GlobalFeatureFlag> updateGlobal(
            @PathVariable String featureKey,
            @Valid @RequestBody FeatureFlagUpdateRequest request) {
        GlobalFeatureFlag updated = featureFlagService.updateGlobal(
                featureKey, request.getEnabled(), request.getReason());
        return ResponseEntity.ok(updated);
    }

    // ── PUT /api/v1/admin/feature-flags/org-type/{orgType}/bulk ──────────

    @AuditFailure(value = AuditEventType.FEATURE_CHANGED)
    @PutMapping(Paths.ADMIN_FF_ORG_TYPE_BULK)
    @Operation(
            summary = "Bulk enable or disable all org-type flag defaults",
            description = "Sets the default state for every globally-enabled ORG-scope flag for the given " +
                          "org type (B2B) in a single atomic operation. " +
                          "Globally-disabled flags are skipped silently.")
    public ResponseEntity<List<OrgTypeFeatureFlag>> bulkUpdateOrgTypeFlags(
            @PathVariable String orgType,
            @Valid @RequestBody FeatureFlagUpdateRequest request) {
        return ResponseEntity.ok(
                featureFlagService.bulkSetOrgTypeOverrides(orgType, request.getEnabled(), request.getReason()));
    }

    // ── PUT /api/v1/admin/feature-flags/{featureKey}/org-type/{orgType} ──

    @AuditFailure(value = AuditEventType.FEATURE_CHANGED, target = "#featureKey", name = "#featureKey")
    @PutMapping(Paths.ADMIN_FF_ORG_TYPE_KEY)
    @Operation(
            summary = "Set an org-type-level feature flag default",
            description = "Sets the default state for a flag for all organizations of the given type " +
                          "(B2B) that have no org-specific override. " +
                          "Returns 400 if the global flag is disabled or the flag is not org-scoped.")
    public ResponseEntity<OrgTypeFeatureFlag> updateOrgTypeFlag(
            @PathVariable String featureKey,
            @PathVariable String orgType,
            @Valid @RequestBody FeatureFlagUpdateRequest request) {
        OrgTypeFeatureFlag saved = featureFlagService.upsertOrgTypeOverride(
                orgType, featureKey, request.getEnabled(), request.getReason());
        return ResponseEntity.ok(saved);
    }

    // ── DELETE /api/v1/admin/feature-flags/{featureKey}/org-type/{orgType}

    @AuditFailure(value = AuditEventType.FEATURE_OVERRIDE_REMOVED, target = "#featureKey", name = "#featureKey")
    @DeleteMapping(Paths.ADMIN_FF_ORG_TYPE_KEY)
    @Operation(
            summary = "Remove an org-type-level feature flag override",
            description = "Reverts all organizations of the given type to the global default for this flag " +
                          "(unless they have their own org-specific override).")
    public ResponseEntity<Map<String, Object>> removeOrgTypeFlag(
            @PathVariable String featureKey,
            @PathVariable String orgType,
            @RequestParam(required = false) String reason) {
        boolean removed = featureFlagService.removeOrgTypeOverride(orgType, featureKey, reason);
        return ResponseEntity.ok(Map.of(
                "featureKey", featureKey,
                "orgType",    orgType,
                "removed",    removed
        ));
    }

    // ── PUT /api/v1/admin/feature-flags/{featureKey}/overrides/{orgId} ───

    @AuditFailure(value = AuditEventType.FEATURE_CHANGED, target = "#featureKey", name = "#featureKey",
            organization = "#organizationId")
    @PutMapping(Paths.ADMIN_FF_ORG_OVERRIDE)
    @Operation(
            summary = "Set an org-specific override on behalf of an organization",
            description = "Allows a super admin to create or update an org-level feature flag override " +
                          "for any organization. The override is locked: it outranks the org-type default, " +
                          "and the org's admin can neither change nor remove it. " +
                          "Returns 400 if the global flag is disabled or the flag is not org-scoped.")
    public ResponseEntity<FeatureFlagDto> updateOrgFlagAsAdmin(
            @PathVariable String featureKey,
            @PathVariable Long organizationId,
            @Valid @RequestBody FeatureFlagUpdateRequest request) {
        OrganizationFeatureFlag saved = featureFlagService.upsertOrgOverrideAsAdmin(
                organizationId, featureKey, request.getEnabled(), request.getReason());
        List<FeatureFlagDto> all = featureFlagService.listEffective(organizationId)
                .stream().map(FeatureFlagDto::from).toList();
        FeatureFlagDto dto = all.stream()
                .filter(f -> f.getFeatureKey().equals(saved.getFeatureKey()))
                .findFirst()
                .orElseThrow();
        return ResponseEntity.ok(dto);
    }

    // ── GET /api/v1/admin/feature-flags/{featureKey}/overrides ───────────

    @GetMapping(Paths.ADMIN_FF_OVERRIDES)
    @Operation(
            summary = "List all org overrides for a flag",
            description = "Returns paginated org-level overrides for the given flag key.")
    public ResponseEntity<Page<OrganizationFeatureFlag>> listOverrides(
            @PathVariable String featureKey,
            Pageable pageable) {
        return ResponseEntity.ok(featureFlagService.listOrgOverrides(featureKey, pageable));
    }

    // ── DELETE /api/v1/admin/feature-flags/{featureKey}/overrides/{orgId} ─

    @AuditFailure(value = AuditEventType.FEATURE_OVERRIDE_REMOVED, target = "#featureKey", name = "#featureKey",
            organization = "#organizationId")
    @DeleteMapping(Paths.ADMIN_FF_ORG_OVERRIDE)
    @Operation(
            summary = "Remove an org's override for a flag",
            description = "Reverts the specified organization to the org-type default or global default for this flag.")
    public ResponseEntity<Map<String, Object>> removeOrgOverride(
            @PathVariable String featureKey,
            @PathVariable Long organizationId,
            @RequestParam(required = false) String reason) {
        boolean removed = featureFlagService.removeOrgOverrideAsAdmin(organizationId, featureKey, reason);
        return ResponseEntity.ok(Map.of(
                "featureKey",     featureKey,
                "organizationId", organizationId,
                "removed",        removed
        ));
    }
}
