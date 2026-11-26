// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import java.util.Base64;
import java.util.Map;

/**
 * An optional binary email attachment carried inside the notification
 * {@code templateFields}.
 *
 * <p>A publisher that needs to send a file embeds it as:
 * <ul>
 *   <li>{@code attachmentBase64}      — base64-encoded file bytes (required)</li>
 *   <li>{@code attachmentFilename}    — download filename (optional)</li>
 *   <li>{@code attachmentContentType} — MIME type (optional)</li>
 * </ul>
 *
 * <p>Named {@code OutboundAttachment} to avoid clashing with the Azure SDK's
 * {@code com.azure.communication.email.models.EmailAttachment}.
 */
public record OutboundAttachment(String filename, String contentType, byte[] content) {

    private static final String DEFAULT_FILENAME = "attachment";
    private static final String DEFAULT_CONTENT_TYPE = "application/octet-stream";

    /**
     * Extract an attachment from the flattened notification model, or return
     * {@code null} if none is present.
     *
     * @throws IllegalArgumentException if {@code attachmentBase64} is not valid base64.
     *         Callers should treat this as "skip the attachment" rather than failing
     *         the whole email.
     */
    public static OutboundAttachment fromModel(Map<String, Object> model) {
        if (model == null) {
            return null;
        }
        Object base64 = model.get("attachmentBase64");
        if (base64 == null || String.valueOf(base64).isBlank()) {
            return null;
        }
        byte[] content = Base64.getDecoder().decode(String.valueOf(base64).trim());
        String filename = asString(model.get("attachmentFilename"), DEFAULT_FILENAME);
        String contentType = asString(model.get("attachmentContentType"), DEFAULT_CONTENT_TYPE);
        return new OutboundAttachment(filename, contentType, content);
    }

    private static String asString(Object value, String fallback) {
        return (value == null || String.valueOf(value).isBlank()) ? fallback : String.valueOf(value);
    }
}
