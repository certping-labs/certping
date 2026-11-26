// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.ProxyService;
import com.certmanagement.constants.Paths;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.certmanagement.security.Permissions.*;
import com.certmanagement.utils.RequestContextLogger;
import com.certmanagement.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

/**
 * REST controller for notification management operations.
 * Proxies requests to the notifier ({@code notification-service.base-url}).
 */
@RestController
@Slf4j
@Validated
@Tag(name = "Notifications", description = "APIs for notification management")
@SecurityRequirement(name = "bearerAuth")
public class NotificationController {

    private final ProxyService proxyService;

    public NotificationController(ProxyService proxyService) {
        this.proxyService = proxyService;
    }

    @GetMapping(value = Paths.NOTIFICATIONS_BASE, produces = MediaType.APPLICATION_JSON_VALUE)
    // Admins only (organization:manage: ORGANIZATION_ADMIN and SUPER_ADMIN): the list names who was
    // sent which account email, so a viewer or analyst never reads it.
    @PreAuthorize("hasPermission(null, '" + ORGANIZATION_MANAGE + "')")
    @Operation(summary = "Get all notifications")
    public ResponseEntity<String> getNotifications(
            @Parameter(description = "Page number") @RequestParam(required = false) Integer page,
            @Parameter(description = "Page size") @RequestParam(required = false) Integer size,
            @Parameter(description = "Status filter") @RequestParam(required = false) String status,
            Authentication authentication) {

        contextLogger().info("Getting notifications");

        Map<String, String> params = new HashMap<>();
        if (page != null) params.put("page", page.toString());
        if (size != null) params.put("size", size.toString());
        if (status != null) params.put("status", status);

        String organizationId = GatewayRequestContext.getOrganizationId();
        if (organizationId != null && !organizationId.isBlank()) {
            params.put("organizationId", organizationId);
        }

        return withoutPayloads(proxyService.get(Paths.NOTIFICATIONS_BASE, params));
    }

    private static final JsonMapper JSON = JsonMapper.builder().build();

    /**
     * The list never carries a row's stored event ({@code payloadJson}), whatever the notifier sends:
     * an older notifier returns it, and it held reset and verification links.
     */
    static ResponseEntity<String> withoutPayloads(ResponseEntity<String> response) {
        if (response == null || response.getBody() == null || !response.getBody().contains("payloadJson")) {
            return response;
        }
        try {
            JsonNode root = JSON.readTree(response.getBody());
            stripPayloads(root);
            return ResponseEntity.status(response.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(JSON.writeValueAsString(root));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).contentType(MediaType.APPLICATION_JSON)
                    .body("{\"success\":false,\"message\":\"Unreadable notification list\"}");
        }
    }

    private static void stripPayloads(JsonNode node) {
        if (node instanceof ObjectNode object) {
            object.remove("payloadJson");
            for (String name : List.copyOf(object.propertyNames())) {
                stripPayloads(object.get(name));
            }
        } else if (node instanceof ArrayNode array) {
            for (int i = 0; i < array.size(); i++) {
                stripPayloads(array.get(i));
            }
        }
    }

    /**
     * Creates a context-aware logger with request tracking IDs from the current request.
     */
    private Logger contextLogger() {
        return RequestContextLogger.getLogger(NotificationController.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
