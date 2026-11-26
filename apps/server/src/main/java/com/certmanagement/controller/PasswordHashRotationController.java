// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.service.PasswordHashRotationService;
import com.certmanagement.service.PasswordHashRotationService.InventoryReport;
import com.certmanagement.service.PasswordHashRotationService.RotationReport;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * Admin endpoints that drive transparent pepper rotation for local-auth
 * {@code users.password_hash} rows. See {@link PasswordHashRotationService}
 * for the rotation playbook and failure semantics.
 *
 * <p>SUPER_ADMIN only: rotation re-encrypts every user's password hash platform-wide, and the
 * inventory covers every organization.
 */
@RestController
@PreAuthorize("hasRole('" + ROLE_SUPER_ADMIN + "')")
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin/password-hash")
@Tag(name = "Password hash rotation", description = "Transparent pepper rotation for local-auth users")
@SecurityRequirement(name = "bearer-jwt")
public class PasswordHashRotationController {

    private final PasswordHashRotationService rotationService;

    @Operation(summary = "Show active pepper version and per-version row counts")
    @GetMapping("/inventory")
    public InventoryReport inventory() {
        return rotationService.inventory();
    }

    /**
     * Drains every {@code users.password_hash} row currently on a non-active
     * pepper version onto the active version. Iterates each old version in
     * turn; runs synchronously. Per-row failures are skipped (counted in the
     * response). Batch-level failures abort the rotation (HTTP 500).
     */
    @Operation(summary = "Re-encrypt all non-active rows onto the active pepper")
    @PostMapping("/rotate")
    public RotationReport rotate(
            @RequestParam(defaultValue = "500") int batchSize) {
        return rotationService.rotateAllToActive(batchSize);
    }
}
