// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.incidents.application;

import com.certmanagement.support.auth.AuthenticatedUser;
import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreatePagerDutyIncidentResponse;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentRequest;
import com.certmanagement.support.incidents.api.model.CreateServiceNowIncidentResponse;
import com.certmanagement.support.incidents.api.model.IncidentPageResponse;
import com.certmanagement.support.incidents.api.model.IncidentResponse;
import com.certmanagement.support.incidents.api.model.InternalPagerDutyIncidentPayload;
import com.certmanagement.support.incidents.api.model.InternalServiceNowIncidentPayload;
import com.certmanagement.support.incidents.api.model.PagerDutyIncidentLink;
import com.certmanagement.support.incidents.domain.Incident;
import com.certmanagement.support.incidents.domain.IncidentCreationSource;
import com.certmanagement.support.incidents.domain.IncidentRepository;
import com.certmanagement.support.incidents.integration.pagerduty.PagerDutyEnqueueResponse;
import com.certmanagement.support.incidents.integration.pagerduty.PagerDutyEventsClient;
import com.certmanagement.support.incidents.integration.servicenow.ServiceNowIncidentClient;
import com.certmanagement.support.integrations.domain.Integration;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.domain.IntegrationRepository;
import com.certmanagement.support.integrations.secret.SecretStore;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class IncidentService {

    private static final int MAX_CUSTOM_DETAILS_DEPTH = 4;
    private static final int MAX_CUSTOM_DETAILS_TEXT_LENGTH = 2_000;

    private final IntegrationRepository integrationRepository;
    private final IncidentRepository incidentRepository;
    private final IncidentAuditService incidentAuditService;
    private final SecretStore secretStore;
    private final PagerDutyEventsClient pagerDutyEventsClient;
    private final ServiceNowIncidentClient serviceNowIncidentClient;

    public IncidentService(
            IntegrationRepository integrationRepository,
            IncidentRepository incidentRepository,
            IncidentAuditService incidentAuditService,
            SecretStore secretStore,
            PagerDutyEventsClient pagerDutyEventsClient,
            ServiceNowIncidentClient serviceNowIncidentClient) {
        this.integrationRepository = integrationRepository;
        this.incidentRepository = incidentRepository;
        this.incidentAuditService = incidentAuditService;
        this.secretStore = secretStore;
        this.pagerDutyEventsClient = pagerDutyEventsClient;
        this.serviceNowIncidentClient = serviceNowIncidentClient;
    }

    @Transactional
    public CreatePagerDutyIncidentResponse createPagerDutyIncident(AuthenticatedUser user, CreatePagerDutyIncidentRequest request) {
        return createPagerDutyIncidentForOrganization(
                organizationId(user),
                user.userId(),
                IncidentCreationSource.PUBLIC_API,
                request.alertId(),
                request.title(),
                request.source(),
                request.severity(),
                request.dedupKey(),
                request.component(),
                request.group(),
                request.className(),
                request.customDetails(),
                request.links());
    }

    @Transactional
    public CreatePagerDutyIncidentResponse createInternalPagerDutyIncident(long organizationId, InternalPagerDutyIncidentPayload request) {
        return createPagerDutyIncidentForOrganization(
                organizationId,
                null,
                IncidentCreationSource.INTERNAL_API,
                request.alertId(),
                request.title(),
                request.source(),
                request.severity(),
                request.dedupKey(),
                request.component(),
                request.group(),
                request.className(),
                request.customDetails(),
                request.links());
    }

    @Transactional
    public CreateServiceNowIncidentResponse createServiceNowIncident(AuthenticatedUser user, CreateServiceNowIncidentRequest request) {
        return createServiceNowIncidentForOrganization(
                organizationId(user),
                user.userId(),
                IncidentCreationSource.PUBLIC_API,
                request.alertId(),
                request.shortDescription(),
                request.description(),
                request.impact(),
                request.urgency(),
                request.category(),
                request.subcategory(),
                request.assignmentGroup(),
                request.businessService(),
                request.configurationItem(),
                request.callerId(),
                request.correlationId(),
                request.correlationDisplay(),
                request.comments(),
                request.workNotes());
    }

    @Transactional
    public CreateServiceNowIncidentResponse createInternalServiceNowIncident(long organizationId, InternalServiceNowIncidentPayload request) {
        return createServiceNowIncidentForOrganization(
                organizationId,
                null,
                IncidentCreationSource.INTERNAL_API,
                request.alertId(),
                request.shortDescription(),
                request.description(),
                request.impact(),
                request.urgency(),
                request.category(),
                request.subcategory(),
                request.assignmentGroup(),
                request.businessService(),
                request.configurationItem(),
                request.callerId(),
                request.correlationId(),
                request.correlationDisplay(),
                request.comments(),
                request.workNotes());
    }

    @Transactional(readOnly = true)
    public IncidentPageResponse listIncidents(AuthenticatedUser user, int page, int size) {
        Page<Incident> incidents = incidentRepository.findByOrganizationIdOrderByCreatedAtDesc(
                organizationId(user),
                PageRequest.of(page, size));

        return new IncidentPageResponse(
                incidents.getNumber(),
                incidents.getSize(),
                incidents.getTotalElements(),
                incidents.getTotalPages(),
                incidents.stream().map(this::toIncidentResponse).toList());
    }

    private CreatePagerDutyIncidentResponse createPagerDutyIncidentForOrganization(
            long organizationId,
            Long actorUserId,
            IncidentCreationSource source,
            Long alertId,
            String title,
            String incidentSource,
            com.certmanagement.support.incidents.api.model.PagerDutyIncidentSeverity severity,
            String dedupKey,
            String component,
            String group,
            String className,
            Map<String, Object> customDetails,
            List<PagerDutyIncidentLink> links) {
        validateOrganizationId(organizationId);
        validatePagerDutyRequest(title, incidentSource, dedupKey, component, group, className, customDetails, links);

        String incidentReference = effectivePagerDutyReference(alertId, dedupKey);

        try {
            Integration integration = findActiveIncidentIntegration(
                    organizationId,
                    IntegrationProvider.PAGERDUTY,
                    "Active PagerDuty integration not found");
            String routingKey = requiredSecretValue(integration, "routing_key");
            PagerDutyEnqueueResponse response = pagerDutyEventsClient.triggerIncident(toPagerDutyPayload(
                    routingKey,
                    title,
                    incidentSource,
                    severity,
                    incidentReference,
                    component,
                    group,
                    className,
                    customDetails,
                    links));

            String resolvedReference = StringUtils.hasText(response.dedupKey()) ? response.dedupKey() : incidentReference;
            Incident incident = incidentRepository.saveAndFlush(new Incident(
                    organizationId,
                    actorUserId,
                    source,
                    IntegrationProvider.PAGERDUTY,
                    alertId,
                    title.trim(),
                    null,
                    requiredExternalReference(resolvedReference),
                    null));

            incidentAuditService.recordSuccess(incident);

            return new CreatePagerDutyIncidentResponse(response.status(), response.message(), response.dedupKey());
        } catch (Exception exception) {
            incidentAuditService.recordFailure(
                    organizationId,
                    source,
                    IntegrationProvider.PAGERDUTY,
                    translatedException(exception));
            throw translatedException(exception);
        }
    }

    private CreateServiceNowIncidentResponse createServiceNowIncidentForOrganization(
            long organizationId,
            Long actorUserId,
            IncidentCreationSource source,
            Long alertId,
            String shortDescription,
            String description,
            com.certmanagement.support.incidents.api.model.ServiceNowIncidentImpact impact,
            com.certmanagement.support.incidents.api.model.ServiceNowIncidentUrgency urgency,
            String category,
            String subcategory,
            String assignmentGroup,
            String businessService,
            String configurationItem,
            String callerId,
            String correlationId,
            String correlationDisplay,
            String comments,
            String workNotes) {
        validateOrganizationId(organizationId);
        validateServiceNowRequest(description, category, subcategory, assignmentGroup, businessService, configurationItem, callerId, correlationId, correlationDisplay, comments, workNotes);

        String effectiveCorrelationId = effectiveServiceNowCorrelationId(alertId, correlationId);
        Map<String, Object> payload = toServiceNowPayload(
                shortDescription,
                description,
                impact,
                urgency,
                category,
                subcategory,
                assignmentGroup,
                businessService,
                configurationItem,
                callerId,
                effectiveCorrelationId,
                correlationDisplay,
                comments,
                workNotes);

        try {
            Integration integration = findActiveIncidentIntegration(
                    organizationId,
                    IntegrationProvider.SERVICENOW_ITSM,
                    "Active ServiceNow ITSM integration not found");
            URI instanceUrl = requiredConfigUri(integration, "instance_url");
            String oauthScope = optionalConfigText(integration, "oauth_scope");
            Map<String, String> secrets = requiredSecretValues(integration);

            ServiceNowIncidentClient.ServiceNowIncidentCreateResult response = serviceNowIncidentClient.createIncident(
                    instanceUrl,
                    oauthScope,
                    payload,
                    secrets);

            Incident incident = incidentRepository.saveAndFlush(new Incident(
                    organizationId,
                    actorUserId,
                    source,
                    IntegrationProvider.SERVICENOW_ITSM,
                    alertId,
                    shortDescription.trim(),
                    response.sysId(),
                    requiredExternalReference(response.number()),
                    response.displayUrl()));

            incidentAuditService.recordSuccess(incident);

            return new CreateServiceNowIncidentResponse(
                    response.sysId(),
                    response.number(),
                    response.recordUrl(),
                    response.displayUrl());
        } catch (Exception exception) {
            incidentAuditService.recordFailure(
                    organizationId,
                    source,
                    IntegrationProvider.SERVICENOW_ITSM,
                    translatedException(exception));
            throw translatedException(exception);
        }
    }

    private IncidentResponse toIncidentResponse(Incident incident) {
        return new IncidentResponse(
                incident.getId(),
                incident.getProvider(),
                incident.getSource(),
                incident.getActorUserId(),
                incident.getAlertId(),
                incident.getSummary(),
                incident.getExternalIncidentId(),
                incident.getExternalReference(),
                incident.getExternalUrl(),
                incident.getCreatedAt());
    }

    private Map<String, Object> toPagerDutyPayload(
            String routingKey,
            String title,
            String source,
            com.certmanagement.support.incidents.api.model.PagerDutyIncidentSeverity severity,
            String dedupKey,
            String component,
            String group,
            String className,
            Map<String, Object> customDetails,
            List<PagerDutyIncidentLink> links) {
        Map<String, Object> eventPayload = new LinkedHashMap<>();
        eventPayload.put("summary", title.trim());
        eventPayload.put("source", source.trim());
        eventPayload.put("severity", severity.pagerDutyValue());
        putIfPresent(eventPayload, "component", component);
        putIfPresent(eventPayload, "group", group);
        putIfPresent(eventPayload, "class", className);
        if (customDetails != null && !customDetails.isEmpty()) {
            eventPayload.put("custom_details", Map.copyOf(customDetails));
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("routing_key", routingKey);
        payload.put("event_action", "trigger");
        payload.put("payload", eventPayload);
        putIfPresent(payload, "dedup_key", dedupKey);
        if (links != null && !links.isEmpty()) {
            payload.put("links", links.stream().map(this::toPagerDutyLink).toList());
        }
        return payload;
    }

    private Map<String, String> toPagerDutyLink(PagerDutyIncidentLink link) {
        return Map.of(
                "href", link.href().trim(),
                "text", link.text().trim());
    }

    private Map<String, Object> toServiceNowPayload(
            String shortDescription,
            String description,
            com.certmanagement.support.incidents.api.model.ServiceNowIncidentImpact impact,
            com.certmanagement.support.incidents.api.model.ServiceNowIncidentUrgency urgency,
            String category,
            String subcategory,
            String assignmentGroup,
            String businessService,
            String configurationItem,
            String callerId,
            String correlationId,
            String correlationDisplay,
            String comments,
            String workNotes) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("short_description", shortDescription.trim());
        putIfPresent(payload, "description", description);
        putIfPresent(payload, "category", category);
        putIfPresent(payload, "subcategory", subcategory);
        putIfPresent(payload, "assignment_group", assignmentGroup);
        putIfPresent(payload, "business_service", businessService);
        putIfPresent(payload, "cmdb_ci", configurationItem);
        putIfPresent(payload, "caller_id", callerId);
        putIfPresent(payload, "correlation_id", correlationId);
        putIfPresent(payload, "correlation_display", correlationDisplay);
        putIfPresent(payload, "comments", comments);
        putIfPresent(payload, "work_notes", workNotes);
        if (impact != null) {
            payload.put("impact", impact.serviceNowValue());
        }
        if (urgency != null) {
            payload.put("urgency", urgency.serviceNowValue());
        }
        return payload;
    }

    private void validatePagerDutyRequest(
            String title,
            String source,
            String dedupKey,
            String component,
            String group,
            String className,
            Map<String, Object> customDetails,
            List<PagerDutyIncidentLink> links) {
        validateOptionalText("dedupKey", dedupKey);
        validateOptionalText("component", component);
        validateOptionalText("group", group);
        validateOptionalText("className", className);
        if (links != null) {
            links.forEach(this::validateLink);
        }
        if (customDetails != null) {
            customDetails.forEach((key, value) -> {
                if (!StringUtils.hasText(key)) {
                    throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "customDetails contains a blank key");
                }
                if (value == null) {
                    throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "customDetails." + key + " must not be null");
                }
                validateCustomDetailsValue("customDetails." + key, value, 1);
            });
        }
        if (!StringUtils.hasText(title) || !StringUtils.hasText(source)) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "Incident payload is invalid");
        }
    }

    private void validateCustomDetailsValue(String path, Object value, int depth) {
        if (depth > MAX_CUSTOM_DETAILS_DEPTH) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + " is nested too deeply");
        }
        if (value instanceof String text && text.length() > MAX_CUSTOM_DETAILS_TEXT_LENGTH) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + " is too long");
        }
        if (value instanceof Map<?, ?> map) {
            if (map.size() > 50) {
                throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + " contains too many fields");
            }
            map.forEach((nestedKey, nestedValue) -> {
                if (!(nestedKey instanceof String key) || !StringUtils.hasText(key)) {
                    throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + " contains a blank key");
                }
                if (nestedValue == null) {
                    throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + "." + key + " must not be null");
                }
                validateCustomDetailsValue(path + "." + key, nestedValue, depth + 1);
            });
            return;
        }
        if (value instanceof List<?> list) {
            if (list.size() > 50) {
                throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + " contains too many items");
            }
            for (int index = 0; index < list.size(); index++) {
                Object nestedValue = list.get(index);
                if (nestedValue == null) {
                    throw new ApiException(400, "INCIDENT_REQUEST_INVALID", path + "[" + index + "] must not be null");
                }
                validateCustomDetailsValue(path + "[" + index + "]", nestedValue, depth + 1);
            }
        }
    }

    private void validateServiceNowRequest(
            String description,
            String category,
            String subcategory,
            String assignmentGroup,
            String businessService,
            String configurationItem,
            String callerId,
            String correlationId,
            String correlationDisplay,
            String comments,
            String workNotes) {
        validateOptionalText("description", description);
        validateOptionalText("category", category);
        validateOptionalText("subcategory", subcategory);
        validateOptionalText("assignmentGroup", assignmentGroup);
        validateOptionalText("businessService", businessService);
        validateOptionalText("configurationItem", configurationItem);
        validateOptionalText("callerId", callerId);
        validateOptionalText("correlationId", correlationId);
        validateOptionalText("correlationDisplay", correlationDisplay);
        validateOptionalText("comments", comments);
        validateOptionalText("workNotes", workNotes);
    }

    private void validateLink(PagerDutyIncidentLink link) {
        try {
            URI uri = URI.create(link.href().trim());
            String scheme = uri.getScheme();
            if (!StringUtils.hasText(uri.getHost()) || (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme))) {
                throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "links.href must be an absolute http or https URL");
            }
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "links.href must be an absolute http or https URL");
        }
    }

    private void validateOptionalText(String field, String value) {
        if (value != null && !StringUtils.hasText(value)) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", field + " must not be blank");
        }
    }

    private void putIfPresent(Map<String, Object> target, String key, String value) {
        if (StringUtils.hasText(value)) {
            target.put(key, value.trim());
        }
    }

    private void putIfPresent(Map<String, Object> target, String key, Long value) {
        if (value != null) {
            target.put(key, value);
        }
    }

    private String requiredExternalReference(String value) {
        if (!StringUtils.hasText(value)) {
            throw new ApiException(502, "INCIDENT_RESPONSE_INVALID", "Downstream incident response is invalid");
        }
        return value.trim();
    }

    private String effectivePagerDutyReference(Long alertId, String dedupKey) {
        return StringUtils.hasText(dedupKey) ? dedupKey.trim() : alertId == null ? null : Long.toString(alertId);
    }

    private String effectiveServiceNowCorrelationId(Long alertId, String correlationId) {
        return StringUtils.hasText(correlationId) ? correlationId.trim() : alertId == null ? null : Long.toString(alertId);
    }

    private String requiredSecretValue(Integration integration, String key) {
        String secretName = integration.getSecretRef(key);
        if (!StringUtils.hasText(secretName)) {
            throw new ApiException(500, "INTEGRATION_SECRET_REFERENCE_INVALID", "Integration secret reference is invalid");
        }

        String secretValue = secretStore.readSecret(secretName);
        if (!StringUtils.hasText(secretValue)) {
            throw new ApiException(500, "INTEGRATION_SECRET_REFERENCE_INVALID", "Integration secret reference is invalid");
        }
        return secretValue;
    }

    private Map<String, String> requiredSecretValues(Integration integration) {
        Map<String, String> resolved = new LinkedHashMap<>();
        integration.getSecretRefs().keySet().forEach(key -> resolved.put(key, requiredSecretValue(integration, key)));
        return Map.copyOf(resolved);
    }

    private URI requiredConfigUri(Integration integration, String key) {
        Object rawValue = integration.getConfig().get(key);
        if (!(rawValue instanceof String value) || !StringUtils.hasText(value)) {
            throw new ApiException(500, "INTEGRATION_CONFIGURATION_INVALID", "Integration configuration is invalid");
        }
        try {
            return URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(500, "INTEGRATION_CONFIGURATION_INVALID", "Integration configuration is invalid");
        }
    }

    private String optionalConfigText(Integration integration, String key) {
        Object rawValue = integration.getConfig().get(key);
        if (rawValue == null) {
            return null;
        }
        if (rawValue instanceof String value && StringUtils.hasText(value)) {
            return value;
        }
        throw new ApiException(500, "INTEGRATION_CONFIGURATION_INVALID", "Integration configuration is invalid");
    }

    private Integration findActiveIncidentIntegration(long organizationId, IntegrationProvider provider, String notFoundMessage) {
        return integrationRepository.findByOrganizationIdAndProviderAndDeletedAtIsNull(organizationId, provider)
                .orElseThrow(() -> new ApiException(404, "INTEGRATION_NOT_FOUND", notFoundMessage));
    }

    private ApiException translatedException(Exception exception) {
        if (exception instanceof ApiException apiException) {
            return apiException;
        }
        return new ApiException(500, "INCIDENT_OPERATION_FAILED", "Incident operation failed");
    }

    private void validateOrganizationId(long organizationId) {
        if (organizationId <= 0) {
            throw new ApiException(400, "INCIDENT_REQUEST_INVALID", "orgId must be positive");
        }
    }

    private long organizationId(AuthenticatedUser user) {
        try {
            return Long.parseLong(user.organizationId());
        } catch (NumberFormatException exception) {
            throw new ApiException(401, "AUTH_TOKEN_INVALID", "Authentication failed");
        }
    }
}
