// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.Paths;
import com.certmanagement.dto.notification.NotificationSettingsRequest;
import com.certmanagement.dto.notification.NotificationSettingsResponse;
import com.certmanagement.service.notification.NotificationPreferenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.ORGANIZATION_MANAGE;
import static com.certmanagement.security.Permissions.ROLE_SUPER_ADMIN;

/**
 * The informational notifications an organization's admins turned off, for email and integrations
 * alike. Only the organization's admins change them ({@code organization:manage} comes with that role
 * alone); a super admin may read them for support but never decides what a customer receives. Both
 * answer 423 while notification settings are off for the organization.
 */
@RestController
@Tag(name = "Notification settings", description = "Informational notifications an organization turned off")
public class NotificationSettingsController {

    private final NotificationPreferenceService preferences;

    public NotificationSettingsController(NotificationPreferenceService preferences) {
        this.preferences = preferences;
    }

    @GetMapping(Paths.ORG_NOTIFICATION_SETTINGS)
    @PreAuthorize("hasPermission(#orgId, 'ORGANIZATION', '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "List the notification categories an organization can turn off and whether each is sent")
    public ResponseEntity<NotificationSettingsResponse> getNotificationSettings(@PathVariable Long orgId) {
        return ResponseEntity.ok(NotificationSettingsResponse.of(preferences.muted(orgId)));
    }

    @AuditFailure(value = AuditEventType.NOTIFICATION_SETTINGS_CHANGED, target = "#orgId", organization = "#orgId")
    @PutMapping(Paths.ORG_NOTIFICATION_SETTINGS)
    @PreAuthorize("hasPermission(#orgId, 'ORGANIZATION', '" + ORGANIZATION_MANAGE + "')"
            + " and !hasRole('" + ROLE_SUPER_ADMIN + "')")
    @Operation(summary = "Replace the notification categories an organization turned off",
            description = "Organization admins only. The list is complete: every category not in it is sent.")
    public ResponseEntity<NotificationSettingsResponse> setNotificationSettings(
            @PathVariable Long orgId, @RequestBody NotificationSettingsRequest body) {
        return ResponseEntity.ok(NotificationSettingsResponse.of(preferences.replaceMuted(orgId, body.muted())));
    }
}
