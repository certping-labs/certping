// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig;

import tools.jackson.databind.JsonNode;
import lombok.Data;

@Data
public class KubernetesDeploymentConfigRequest {
    private Boolean useDefault;
    private JsonNode nsSecretMap;
}
