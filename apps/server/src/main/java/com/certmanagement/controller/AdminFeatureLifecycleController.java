// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.constants.Paths;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse;
import com.certmanagement.service.lifecycle.BaselinePreviewService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * Super-admin views of the feature lifecycle. Every endpoint is for SUPER_ADMIN only, checked by role
 * on the class so an endpoint added later cannot miss it.
 */
@RestController
@RequiredArgsConstructor
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
@Tag(name = "Admin Feature Lifecycle", description = "Super-admin feature lifecycle rollout views")
public class AdminFeatureLifecycleController {

    private final BaselinePreviewService baselinePreviewService;

    @GetMapping(Paths.ADMIN_FEATURE_LIFECYCLE_BASELINE_PREVIEW)
    @Operation(
            summary = "Preview the feature lifecycle baseline",
            description = "Per platform-pausable feature, the organizations and records the baseline would pause "
                    + "(silently) once FEATURE_LIFECYCLE_RECONCILE is turned on, by the layer that "
                    + "has the feature off: GLOBAL, ORG_OVERRIDE or ORG_TYPE. Read only.")
    public ResponseEntity<BaselinePreviewResponse> baselinePreview() {
        return ResponseEntity.ok(baselinePreviewService.preview());
    }
}
