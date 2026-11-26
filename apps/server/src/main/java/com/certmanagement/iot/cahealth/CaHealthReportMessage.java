// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.cahealth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class CaHealthReportMessage {
    private Integer reportVersion;
    private String organizationId;
    private String respondedAt;
    private List<Connector> connectors;

    @Data
    @NoArgsConstructor
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Connector {
        private String caProvider;
        private String connectorId;
        private Boolean enabled;
        private String status;
        private String checkedAt;
        private Long latencyMs;
        private String endpoint;
        private Object product;
        private String authMethod;
        private List<String> capabilities;
        private List<Object> profiles;
        private List<Object> issues;
    }
}
