// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.auth.CurrentAuthenticatedUser;
import com.certmanagement.support.integrations.api.model.CreateIntegrationRequest;
import com.certmanagement.support.integrations.api.model.IntegrationResponse;
import com.certmanagement.support.integrations.api.model.UpdateIntegrationRequest;
import com.certmanagement.support.integrations.application.IntegrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.certmanagement.security.Permissions.INTEGRATIONS_MANAGE;
import static com.certmanagement.security.Permissions.INTEGRATIONS_VIEW;

@RestController
@FeatureGated(FeatureFlags.INTEGRATIONS)
@Validated
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Integrations", description = "Manage organization-level enterprise integrations and their credential references.")
public class IntegrationController {

    private final CurrentAuthenticatedUser currentAuthenticatedUser;
    private final IntegrationService integrationService;

    @PostMapping(value = Paths.INTEGRATIONS_BASE, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INTEGRATIONS_MANAGE + "')")
    @Operation(summary = "Create an integration",
            description = "Creates a provider-specific integration (Slack/Teams/PagerDuty/ServiceNow ITSM) for the authenticated organization. Raw secrets are stored in Azure Key Vault; the database only stores secret references.")
    @AuditFailure(AuditEventType.INTEGRATION_CREATED)
    public ResponseEntity<IntegrationResponse> createIntegration(@Valid @RequestBody CreateIntegrationRequest request) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        IntegrationResponse response = integrationService.createIntegration(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping(value = Paths.INTEGRATIONS_BASE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INTEGRATIONS_VIEW + "')")
    @Operation(summary = "List active integrations",
            description = "Returns active integrations for the authenticated organization. Webhook URLs and routing keys are never returned.")
    public List<IntegrationResponse> listIntegrations() {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return integrationService.listIntegrations(user);
    }

    @GetMapping(value = Paths.INTEGRATIONS_ID, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INTEGRATIONS_VIEW + "')")
    @Operation(summary = "Get an active integration",
            description = "Returns one active integration for the authenticated organization. Secrets are never returned.")
    public IntegrationResponse getIntegration(@PathVariable long integrationId) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return integrationService.getIntegration(user, integrationId);
    }

    @PutMapping(value = Paths.INTEGRATIONS_ID, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INTEGRATIONS_MANAGE + "')")
    @Operation(summary = "Update an integration",
            description = "Replaces the provider-specific credentials for an existing integration. The integration id stays the same.")
    @AuditFailure(value = AuditEventType.INTEGRATION_UPDATED, target = "#integrationId")
    public IntegrationResponse updateIntegration(@PathVariable long integrationId,
                                                 @Valid @RequestBody UpdateIntegrationRequest request) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return integrationService.updateIntegration(user, integrationId, request);
    }

    @DeleteMapping(Paths.INTEGRATIONS_ID)
    @PreAuthorize("hasPermission(null, '" + INTEGRATIONS_MANAGE + "')")
    @Operation(summary = "Soft delete an integration",
            description = "Marks an integration as deleted. Hard deletes are not supported.")
    @AuditFailure(value = AuditEventType.INTEGRATION_DELETED, target = "#integrationId")
    public ResponseEntity<Void> deleteIntegration(@PathVariable long integrationId) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        integrationService.deleteIntegration(user, integrationId);
        return ResponseEntity.noContent().build();
    }
}
