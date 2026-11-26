// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

/**
 * Deployment credential JSON for Akamai CPS (third-party enrollment) rotations.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AkamaiCpsDeploymentCredential {
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
