// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesBackendServiceRef;
import com.certping.agent.model.message.KubernetesCertificateUsage;

import java.util.List;

record KubernetesCertificateUsageCandidate(
        String certificateSourceKind,
        String certificateNamespace,
        String certificateName,
        KubernetesCertificateUsage usage,
        List<KubernetesBackendServiceRef> backendServices) {
}
