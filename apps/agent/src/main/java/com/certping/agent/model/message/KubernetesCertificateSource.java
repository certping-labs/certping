// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Builder;
import lombok.Value;

@Value
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class KubernetesCertificateSource {
    String apiVersion;
    String kind;
    String namespace;
    String name;
    String uid;
    String resourceVersion;
    String type;
    String fingerprintSha256;
}
