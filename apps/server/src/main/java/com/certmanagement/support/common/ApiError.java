// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.common;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Standard API error envelope")
public record ApiError(
        @Schema(description = "HTTP status code", example = "400")
        int status,

        @Schema(description = "HTTP status text", example = "Bad Request")
        String error,

        @Schema(description = "Stable machine-readable error code", example = "REQUEST_VALIDATION_FAILED")
        String code,

        @Schema(description = "Sanitized end-user message", example = "Request validation failed")
        String message,

        @Schema(description = "Request correlation id", example = "c4638ff0-c62a-4e5c-a34c-f0a4df16d53d")
        String requestId,

        @Schema(description = "Optional validation or domain-specific issues")
        Object issues
) {

    public static ApiError of(int status, String code, String message, String requestId) {
        return new ApiError(status, label(status), code, message, requestId, null);
    }

    public static ApiError of(int status, String code, String message, String requestId, Object issues) {
        return new ApiError(status, label(status), code, message, requestId, issues);
    }

    private static String label(int status) {
        return switch (status) {
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 409 -> "Conflict";
            case 412 -> "Precondition Failed";
            case 429 -> "Too Many Requests";
            case 502 -> "Bad Gateway";
            case 504 -> "Gateway Timeout";
            default -> status >= 500 ? "Internal Server Error" : "Request Failed";
        };
    }
}
