// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.common;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import java.time.Instant;
import java.util.List;

/**
 * Standard error response DTO for API errors.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Standard error response for API errors")
public class ErrorResponse {

    @Schema(description = "HTTP status code", example = "400")
    private int status;

    @Schema(description = "Error type", example = "Bad Request")
    private String error;

    @Schema(description = "Error message", example = "Validation failed for request")
    private String message;

    @Schema(description = "Request path that caused the error", example = "/api/v1/organizations")
    private String path;

    @Schema(description = "Timestamp when the error occurred", example = "2024-01-15T10:30:00Z")
    private Instant timestamp;

    @Schema(description = "List of field-specific validation errors")
    private List<FieldError> fieldErrors;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    @Schema(description = "Field-specific validation error")
    public static class FieldError {
        @Schema(description = "Name of the field with error", example = "email")
        private String field;

        @Schema(description = "Error message for the field", example = "must not be blank")
        private String message;

        @Schema(description = "The value that was rejected", example = "invalid-email")
        private Object rejectedValue;
    }
}
