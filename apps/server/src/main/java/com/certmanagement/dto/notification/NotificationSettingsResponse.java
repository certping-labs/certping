// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.notification;

import com.certmanagement.service.notification.NotificationCategory;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Every notification category an organization can turn off, in a fixed order, and whether it is sent. */
@Schema(description = "The notification categories an organization can turn off")
public record NotificationSettingsResponse(List<Category> categories) {

    @Schema(description = "One category and whether it is sent")
    public record Category(
            @Schema(example = "CERTIFICATE_ACTIVITY") String key,
            @Schema(description = "False when the organization turned it off") boolean enabled) {
    }

    public static NotificationSettingsResponse of(Set<NotificationCategory> muted) {
        return new NotificationSettingsResponse(Arrays.stream(NotificationCategory.values())
                .map(category -> new Category(category.name(), !muted.contains(category)))
                .toList());
    }
}
