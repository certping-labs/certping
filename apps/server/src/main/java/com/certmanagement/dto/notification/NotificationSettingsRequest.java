// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.notification;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/** The complete list of notification categories to turn off; categories not listed are sent. */
@Schema(description = "Notification categories to turn off; every category not listed is sent")
public record NotificationSettingsRequest(
        @Schema(description = "Category keys", example = "[\"CERTIFICATE_ACTIVITY\"]",
                requiredMode = Schema.RequiredMode.REQUIRED)
        List<String> muted) {
}
