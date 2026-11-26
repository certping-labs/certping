// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.alert;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for {@code PATCH /api/v1/alerts/{id}}.
 * Toggles the {@code unread} flag on an alert.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateAlertRequest {

    /** Set to {@code false} to mark the alert as read, {@code true} to mark as unread. */
    private Boolean unread;
}
