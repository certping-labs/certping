// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.controller;

import com.certping.notification.model.NotificationEvent;
import com.certping.notification.model.NotificationRecord;
import com.certping.notification.model.NotificationStatus;
import com.certping.notification.repository.NotificationRepository;
import com.certping.notification.service.NotificationService;
import com.certping.notification.service.UndeliveredEmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Value;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import com.certping.notification.utils.RequestContextLogger;
import com.certping.notification.interceptor.RequestContextInterceptor;
import org.slf4j.Logger;

@RestController
@RequestMapping("/api/notifications")
@RequiredArgsConstructor
@Slf4j
public class NotificationController {

    static final int DEFAULT_PAGE_SIZE = 20;
    static final int MAX_PAGE_SIZE     = 100;

    private final NotificationService notificationService;
    private final NotificationRepository notificationRepository;
    private final UndeliveredEmailService undeliveredEmailService;

    @Value("${notifier.delivery.replay-token:}")
    private String replayToken;

    @PostMapping("/admin/replay-undelivered")
    public ResponseEntity<Map<String, Object>> replayUndelivered(
            @RequestHeader(value = "X-Notifier-Replay-Token", required = false) String suppliedToken) {
        if (replayToken == null || replayToken.isBlank() || suppliedToken == null
                || !MessageDigest.isEqual(replayToken.getBytes(StandardCharsets.UTF_8),
                suppliedToken.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(403).body(Map.of("success", false));
        }
        return ResponseEntity.ok(Map.of("success", true, "replayed", undeliveredEmailService.replay()));
    }

    @PostMapping("/process")
    public ResponseEntity<String> processNotifications(@RequestBody List<NotificationEvent> events) {
        contextLogger().info("Processing {} notification events", events.size());
        notificationService.processNotifications(events);
        return ResponseEntity.ok("Notifications processed successfully");
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getNotifications(
            @RequestParam(required = false) String userId,
            @RequestParam(required = false) String organizationId,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) Integer page,
            @RequestParam(required = false) Integer size) {

        contextLogger().info("Getting notifications for userId: {}, organizationId: {}, status: {}, page: {}, size: {}",
                userId, organizationId, status, page, size);

        if (organizationId == null || organizationId.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "organizationId is required"
            ));
        }

        Page<NotificationRecord> result;
        try {
            Long parsedOrganizationId = Long.parseLong(organizationId);
            Pageable pageable = PageRequest.of(
                    page != null && page >= 0 ? page : 0,
                    size != null && size > 0 ? Math.min(size, MAX_PAGE_SIZE) : DEFAULT_PAGE_SIZE
            );

            if (status != null && !status.isBlank()) {
                NotificationStatus statusEnum = NotificationStatus.valueOf(status.toUpperCase());
                result = notificationRepository.findByOrganizationIdAndStatusOrderByCreatedAtDesc(
                        parsedOrganizationId, statusEnum, pageable);
            } else {
                result = notificationRepository.findByOrganizationIdOrderByCreatedAtDesc(
                        parsedOrganizationId, pageable);
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "success", false,
                    "message", "Invalid parameter: " + e.getMessage()
            ));
        }

        return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Notifications retrieved successfully",
                "data", result.getContent().stream().map(NotificationController::listItem).toList(),
                "page", result.getNumber(),
                "size", result.getSize(),
                "totalElements", result.getTotalElements(),
                "totalPages", result.getTotalPages()
        ));
    }

    /**
     * One row of the list: what was sent, to whom and how it went. Never {@code payloadJson}: the
     * stored event is for redelivery, and even redacted it is not something a list should show.
     */
    static Map<String, Object> listItem(NotificationRecord record) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("id", record.getId());
        item.put("userId", record.getUserId());
        item.put("organizationId", record.getOrganizationId());
        item.put("websiteId", record.getWebsiteId());
        item.put("email", record.getEmail());
        item.put("templateName", record.getTemplateName());
        item.put("subject", record.getSubject());
        item.put("sentBy", record.getSentBy());
        item.put("integrationType", record.getIntegrationType());
        item.put("status", record.getStatus());
        item.put("failureReason", record.getFailureReason());
        item.put("sentAt", record.getSentAt());
        item.put("createdAt", record.getCreatedAt());
        item.put("updatedAt", record.getUpdatedAt());
        item.put("requestId", record.getRequestId());
        item.put("correlationId", record.getCorrelationId());
        return item;
    }

    private Logger contextLogger() {
        return RequestContextLogger.getLogger(NotificationController.class,
                RequestContextInterceptor.getCurrentRequestId(),
                RequestContextInterceptor.getCurrentCorrelationId(),
                RequestContextInterceptor.getCurrentIdempotencyKey());
    }
}
