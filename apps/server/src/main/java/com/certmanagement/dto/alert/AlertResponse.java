// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.alert;

import com.certmanagement.enums.AlertSeverity;
import com.certmanagement.enums.AlertTypeEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;

/**
 * Response DTO for {@code GET /api/v1/alerts}.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AlertResponse {

    private List<Alert> alerts;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Alert {
        private Long         id;
        private AlertTypeEnum alertType;
        private String       status;
        private String       domain;
        private Instant      createdAt;
        /**
         * User-facing summary derived from the (internal) error code. The raw {@code errorDetail}
         * and {@code errorCode} are intentionally NOT exposed here — they may carry internal
         * system detail and remain only on the {@code AlertEntity} for internal logs/audit.
         */
        private String       message;
        /**
         * Per-operation reference id the user can quote when asking for help (the web app puts it in a
         * pre-filled support request). Derived from the alert's correlation id; null when the
         * originating event had none. Carries no system detail.
         */
        private String       correlationId;
        private AlertSeverity severity;
        private Boolean      unread;
    }
}
