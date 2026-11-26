// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.featureflags.FeatureClearRequest;
import com.certmanagement.dto.featureflags.EffectiveFeatureFlagsResponse;
import com.certmanagement.dto.featureflags.FeatureClearResponse;
import com.certmanagement.dto.featureflags.FeatureDisableCheckResponse;
import com.certmanagement.dto.featureflags.FeatureFlagDto;
import com.certmanagement.dto.featureflags.FeatureFlagUpdateRequest;
import com.certmanagement.entity.OrganizationFeatureFlag;
import com.certmanagement.exception.ManagedByCertpingException;
import com.certmanagement.security.CallerPermissions;
import com.certmanagement.security.OrgResolver;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.service.FeatureFlagService.ResolvedFlag;
import com.certmanagement.service.lifecycle.FeatureLifecycleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.certmanagement.security.Permissions.*;

/**
 * Org-scoped feature flag endpoints.
 *
 * <ul>
 *   <li>{@code GET  /api/v1/feature-flags}            — list all flags with effective state for the calling org</li>
 *   <li>{@code GET  /api/v1/feature-flags/effective}  — every flag's effective state, for any member of the org</li>
 *   <li>{@code PUT  /api/v1/feature-flags/{featureKey}} — set/update an org-level override</li>
 *   <li>{@code DELETE /api/v1/feature-flags/{featureKey}} — remove org override (revert to global default)</li>
 *   <li>{@code GET  /api/v1/feature-flags/{featureKey}/disable-check} — what keeps the feature in use</li>
 *   <li>{@code POST /api/v1/feature-flags/{featureKey}/clear} — pause/delete/cancel those records in bulk</li>
 * </ul>
 *
 * <p>While {@code FEATURE_FLAGS_PAGE} is off for the organization, every endpoint here but
 * {@code /effective} answers 403 {@code MANAGED_BY_CERTPING}.
 *
 * <p>Switching a feature off is clear-first: the PUT is refused with 409 {@code FEATURE_IN_USE} while
 * anything of the feature still runs.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Feature Flags", description = "Organization-scoped feature flag management")
public class FeatureFlagController {

    private final FeatureFlagService featureFlagService;
    private final FeatureLifecycleService lifecycleService;

    // ── GET /api/v1/feature-flags ────────────────────────────────────────

    @GetMapping(Paths.FEATURE_FLAGS)
    @PreAuthorize("hasPermission(null, '" + FEATURE_FLAGS_VIEW + "')")
    @Operation(
            summary = "List feature flags for the calling organization",
            description = "The `flags` array lists only the flags this organization can switch: ORG scope and " +
                          "on globally. A feature a super admin turned off is left out rather than shown disabled. " +
                          "403 MANAGED_BY_CERTPING while the feature flags page is off. The `effectiveMap` covers " +
                          "ALL flags (ORG and PLATFORM) with their resolved state so the frontend can hide " +
                          "navigation and pages for features that are off.")
    public ResponseEntity<Map<String, Object>> listFlags() {
        Long orgId = OrgResolver.fromJwt();
        assertPageOpen(orgId);
        List<ResolvedFlag> resolved = featureFlagService.listEffective(orgId);

        // A flag the org cannot change is left out, so an org admin never sees a greyed-out feature.
        List<FeatureFlagDto> flags = resolved.stream()
                .filter(ResolvedFlag::orgControllable)
                .map(FeatureFlagDto::from)
                .toList();

        // Every flag, PLATFORM-scope too: the frontend gates navigation and routes on this map, and a
        // flag missing here would make it fail open onto a feature the backend refuses with 423.
        Map<String, Boolean> effectiveMap = resolved.stream()
                .collect(Collectors.toMap(r -> r.global().getFeatureKey(), ResolvedFlag::effectiveEnabled));

        return ResponseEntity.ok(Map.of(
                "flags",        flags,
                "effectiveMap", effectiveMap
        ));
    }

    // ── GET /api/v1/feature-flags/effective ──────────────────────────────

    @GetMapping(Paths.FEATURE_FLAGS_EFFECTIVE)
    @PreAuthorize("isAuthenticated()")
    @Operation(
            summary = "Effective feature state for the calling organization",
            description = "Every flag (ORG and PLATFORM scope) with whether it is on for the caller's " +
                          "organization, so the frontend can hide what is off. Open to every signed-in member " +
                          "(no feature_flags:view needed). A caller without an organization in the token (a " +
                          "super admin outside an organization) gets an empty map.")
    public ResponseEntity<EffectiveFeatureFlagsResponse> effectiveFlags() {
        Long orgId = OrgResolver.fromJwtOrNull();
        return ResponseEntity.ok(new EffectiveFeatureFlagsResponse(
                orgId == null ? Map.of() : featureFlagService.effectiveMap(orgId)));
    }

    // ── PUT /api/v1/feature-flags/{featureKey} ───────────────────────────

    @AuditFailure(value = AuditEventType.FEATURE_CHANGED, target = "#featureKey", name = "#featureKey")
    @PutMapping(Paths.FEATURE_FLAGS_KEY)
    @PreAuthorize("hasPermission(null, '" + FEATURE_FLAGS_MANAGE + "')")
    @Operation(
            summary = "Set an org-level feature flag override",
            description = "Creates or updates the override for this org. Returns 400 if the flag is not " +
                          "org-scoped, is off globally, or is decided by a platform administrator (a per-org " +
                          "override they set or an org-type \"off\"). Switching a feature off returns 409 " +
                          "FEATURE_IN_USE with the blockers while anything of it still runs. 403 " +
                          "MANAGED_BY_CERTPING while the feature flags page is off.")
    public ResponseEntity<FeatureFlagDto> updateOrgFlag(
            @PathVariable String featureKey,
            @Valid @RequestBody FeatureFlagUpdateRequest request) {
        Long orgId = OrgResolver.fromJwt();
        assertPageOpen(orgId);
        OrganizationFeatureFlag saved = featureFlagService.upsertOrgOverride(
                orgId, featureKey, request.getEnabled(), request.getReason());
        List<FeatureFlagDto> all = featureFlagService.listEffective(orgId)
                .stream().map(FeatureFlagDto::from).toList();
        FeatureFlagDto dto = all.stream()
                .filter(f -> f.getFeatureKey().equals(saved.getFeatureKey()))
                .findFirst()
                .orElseThrow();
        return ResponseEntity.ok(dto);
    }

    // ── DELETE /api/v1/feature-flags/{featureKey} ────────────────────────

    @AuditFailure(value = AuditEventType.FEATURE_OVERRIDE_REMOVED, target = "#featureKey", name = "#featureKey")
    @DeleteMapping(Paths.FEATURE_FLAGS_KEY)
    @PreAuthorize("hasPermission(null, '" + FEATURE_FLAGS_MANAGE + "')")
    @Operation(
            summary = "Remove org-level feature flag override",
            description = "Deletes the org override for this flag, reverting to the org-type default (if set) or " +
                          "global default. Returns 400 if a platform administrator set the override; 403 " +
                          "MANAGED_BY_CERTPING while the feature flags page is off.")
    public ResponseEntity<Map<String, Object>> removeOrgFlag(@PathVariable String featureKey,
                                                             @RequestParam(required = false) String reason) {
        Long orgId = OrgResolver.fromJwt();
        assertPageOpen(orgId);
        boolean removed = featureFlagService.removeOrgOverride(orgId, featureKey, reason);
        return ResponseEntity.ok(Map.of(
                "featureKey", featureKey,
                "removed",    removed,
                "message",    removed
                        ? "Override removed. Feature will now follow the org-type default or global default."
                        : "No override found for this feature in your organization."
        ));
    }

    // ── GET /api/v1/feature-flags/{featureKey}/disable-check ─────────────

    @GetMapping(Paths.FEATURE_FLAGS_DISABLE_CHECK)
    @PreAuthorize("hasPermission(null, '" + FEATURE_FLAGS_MANAGE + "')")
    @Operation(
            summary = "Check whether a feature can be switched off for the calling organization",
            description = "Lists what keeps the feature in use (blockers) with the bulk actions that clear each " +
                          "kind; canDisable is true when there is nothing. Each blocker offers only the actions " +
                          "the caller holds the permission for (the same one the change needs one record at a " +
                          "time). 404 for an unknown feature.")
    public ResponseEntity<FeatureDisableCheckResponse> disableCheck(@PathVariable String featureKey) {
        Long orgId = OrgResolver.fromJwt();
        assertPageOpen(orgId);
        featureFlagService.getGlobal(featureKey);
        return ResponseEntity.ok(FeatureDisableCheckResponse.of(featureKey,
                lifecycleService.blockersFor(orgId, featureKey, CallerPermissions.current())));
    }

    // ── POST /api/v1/feature-flags/{featureKey}/clear ────────────────────

    @AuditFailure(value = AuditEventType.FEATURE_RECORDS_CLEARED, target = "#featureKey", name = "#featureKey")
    @PostMapping(Paths.FEATURE_FLAGS_CLEAR)
    @PreAuthorize("hasPermission(null, '" + FEATURE_FLAGS_MANAGE + "')")
    @Operation(
            summary = "Clear what keeps a feature in use, in bulk",
            description = "Applies one bulk action (PAUSE_ALL, DELETE_ALL, CANCEL_ALL, CLEAR_TARGETS, " +
                          "DISABLE_AUTO_RENEW) to every record of the kind in the calling organization, with the " +
                          "same semantics as one at a time. 400 when the action does not clear that kind " +
                          "(link-only kinds are never cleared in bulk); 403 when the caller lacks the permission " +
                          "the action needs one record at a time (certificate:deploy or certificate:renew), or " +
                          "with MANAGED_BY_CERTPING while the feature flags page is off.")
    public ResponseEntity<FeatureClearResponse> clear(@PathVariable String featureKey,
                                                      @Valid @RequestBody FeatureClearRequest request) {
        Long orgId = OrgResolver.fromJwt();
        assertPageOpen(orgId);
        featureFlagService.getGlobal(featureKey);
        int affected = lifecycleService.clear(orgId, featureKey, request.kind(), request.action(),
                CallerPermissions.current());
        return ResponseEntity.ok(new FeatureClearResponse(request.kind(), request.action(), affected));
    }

    private void assertPageOpen(Long orgId) {
        if (!featureFlagService.isEnabled(FeatureFlags.FEATURE_FLAGS_PAGE, orgId)) {
            throw new ManagedByCertpingException(FeatureFlags.FEATURE_FLAGS_PAGE, FeatureFlags.FEATURE_FLAGS_UNAVAILABLE);
        }
    }
}
