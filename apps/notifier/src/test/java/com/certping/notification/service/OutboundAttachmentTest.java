// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OutboundAttachmentTest {

    @Test
    void fromModel_null_returnsNull() {
        assertThat(OutboundAttachment.fromModel(null)).isNull();
    }

    @Test
    void fromModel_missingBase64_returnsNull() {
        assertThat(OutboundAttachment.fromModel(Map.of("other", "value"))).isNull();
    }

    @Test
    void fromModel_blankBase64_returnsNull() {
        Map<String, Object> model = new HashMap<>();
        model.put("attachmentBase64", "   ");
        assertThat(OutboundAttachment.fromModel(model)).isNull();
    }

    @Test
    void fromModel_nullBase64_returnsNull() {
        Map<String, Object> model = new HashMap<>();
        model.put("attachmentBase64", null);
        assertThat(OutboundAttachment.fromModel(model)).isNull();
    }

    @Test
    void fromModel_validBase64WithAllFields_returnsPopulated() {
        byte[] pdfBytes = "%PDF-1.4 fake".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> model = Map.of(
                "attachmentBase64", Base64.getEncoder().encodeToString(pdfBytes),
                "attachmentFilename", "report.pdf",
                "attachmentContentType", "application/pdf"
        );

        OutboundAttachment result = OutboundAttachment.fromModel(model);

        assertThat(result).isNotNull();
        assertThat(result.filename()).isEqualTo("report.pdf");
        assertThat(result.contentType()).isEqualTo("application/pdf");
        assertThat(result.content()).isEqualTo(pdfBytes);
    }

    @Test
    void fromModel_missingFilename_usesDefault() {
        Map<String, Object> model = Map.of(
                "attachmentBase64", Base64.getEncoder().encodeToString("data".getBytes())
        );

        OutboundAttachment result = OutboundAttachment.fromModel(model);

        assertThat(result.filename()).isEqualTo("attachment");
        assertThat(result.contentType()).isEqualTo("application/octet-stream");
    }

    @Test
    void fromModel_blankFilename_usesDefault() {
        Map<String, Object> model = Map.of(
                "attachmentBase64", Base64.getEncoder().encodeToString("data".getBytes()),
                "attachmentFilename", "   ",
                "attachmentContentType", ""
        );

        OutboundAttachment result = OutboundAttachment.fromModel(model);

        assertThat(result.filename()).isEqualTo("attachment");
        assertThat(result.contentType()).isEqualTo("application/octet-stream");
    }

    @Test
    void fromModel_base64WithSurroundingWhitespace_trimmedThenDecoded() {
        byte[] payload = "hello".getBytes(StandardCharsets.UTF_8);
        String b64 = Base64.getEncoder().encodeToString(payload);
        Map<String, Object> model = Map.of("attachmentBase64", "  " + b64 + "  ");

        OutboundAttachment result = OutboundAttachment.fromModel(model);

        assertThat(result.content()).isEqualTo(payload);
    }

    @Test
    void fromModel_invalidBase64_throwsIllegalArgumentException() {
        Map<String, Object> model = Map.of("attachmentBase64", "!!!not-base64!!!");

        assertThatThrownBy(() -> OutboundAttachment.fromModel(model))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
