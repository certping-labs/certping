// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Value;

import java.util.List;

@Value
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class KubernetesCertificateImpact {
    boolean externallyServed;
    boolean directlyMountedByWorkloads;
    List<String> affectedHostnames;
    List<String> affectedServices;
    List<String> affectedWorkloads;
    String summary;
}
