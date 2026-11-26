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
public class KubernetesCertificateUsage {
    String apiVersion;
    String kind;
    String namespace;
    String name;
    String uid;
    String fieldPath;
    String usageType;
    List<String> hostnames;
    List<KubernetesBackendServiceRef> backendServices;
    List<KubernetesWorkloadRef> affectedWorkloads;
    String confidence;
}
