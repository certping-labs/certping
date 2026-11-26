// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.notification;

import java.util.LinkedHashMap;
import java.util.Map;

public record NotificationContent(
        String title,
        String message,
        String linkUrl,
        String linkText,
        Map<String, String> facts
) {

    public NotificationContent {
        facts = facts == null ? Map.of() : new LinkedHashMap<>(facts);
    }
}
