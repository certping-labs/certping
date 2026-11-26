// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.KubernetesCertificateImpact;
import com.certping.agent.model.message.KubernetesCertificateUsage;

import java.util.List;

record KubernetesMappedCertificateUsage(
        List<KubernetesCertificateUsage> usages,
        KubernetesCertificateImpact impact,
        boolean impactComplete,
        List<String> warnings) {
}
