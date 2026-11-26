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
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentResponse;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentResponse;
import com.certmanagement.support.incidents.api.model.IncidentPageResponse;
import com.certmanagement.support.incidents.application.IncidentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static com.certmanagement.security.Permissions.INCIDENTS_CREATE;
import static com.certmanagement.security.Permissions.INCIDENTS_VIEW;

@RestController
@FeatureGated(FeatureFlags.INTEGRATIONS)
@Validated
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Incidents", description = "Create PagerDuty and ServiceNow ITSM incidents for the authenticated organization.")
public class IncidentController {

    private final CurrentAuthenticatedUser currentAuthenticatedUser;
    private final IncidentService incidentService;

    @GetMapping(value = Paths.INCIDENTS_BASE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INCIDENTS_VIEW + "')")
    @Operation(summary = "List stored incidents",
            description = "Returns paginated incident history for the authenticated organization.")
    public IncidentPageResponse listIncidents(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "50") @Min(1) @Max(100) int size) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return incidentService.listIncidents(user, page, size);
    }

    @PostMapping(value = Paths.INCIDENTS_PAGERDUTY, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INCIDENTS_CREATE + "')")
    @Operation(summary = "Create a PagerDuty incident",
            description = "Triggers a PagerDuty incident through the organization's active PagerDuty integration (Events API v2).")
    @AuditFailure(AuditEventType.INCIDENT_TRIGGERED)
    public ResponseEntity<CreatePagerDutyIncidentResponse> createPagerDutyIncident(
            @Valid @RequestBody CreatePagerDutyIncidentRequest request) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(incidentService.createPagerDutyIncident(user, request));
    }

    @PostMapping(value = Paths.INCIDENTS_SERVICENOW, consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasPermission(null, '" + INCIDENTS_CREATE + "')")
    @Operation(summary = "Create a ServiceNow ITSM incident",
            description = "Creates a ServiceNow incident through the organization's active ServiceNow ITSM integration (OAuth client-credentials).")
    @AuditFailure(AuditEventType.INCIDENT_TRIGGERED)
    public ResponseEntity<CreateServiceNowIncidentResponse> createServiceNowIncident(
            @Valid @RequestBody CreateServiceNowIncidentRequest request) {
        AuthenticatedUser user = currentAuthenticatedUser.getRequired();
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(incidentService.createServiceNowIncident(user, request));
    }
}
