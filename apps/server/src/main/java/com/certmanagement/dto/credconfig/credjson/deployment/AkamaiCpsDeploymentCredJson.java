// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

/**
 * Akamai CPS (third-party enrollment) deployment.
 *
 * <p><b>Required (outer):</b> {@code host}, {@code clientToken}, {@code accessToken},
 * {@code clientSecret}, {@code enrollments} (non-empty).
 * <p><b>Optional (outer):</b> {@code pollIntervalSeconds}, {@code pollTimeoutMinutes}, {@code waitForStatus}.
 *
 * <p><b>{@link AkamaiEnrollment} — all fields REQUIRED per entry:</b>
 * {@code enrollmentId, contractId, commonName, domains, network, certType}.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AkamaiCpsDeploymentCredJson implements CredJsonPayload {
    private String host;
    private String clientToken;
    private String accessToken;
    private String clientSecret;
    private List<AkamaiEnrollment> enrollments;
    private Integer pollIntervalSeconds;
    private Integer pollTimeoutMinutes;
    private String waitForStatus;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AkamaiEnrollment {
        private String enrollmentId;
        private String contractId;
        private String commonName;
        private List<String> domains;
        private String network;
        private String certType;
    }
}
