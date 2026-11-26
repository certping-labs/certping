// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import io.kubernetes.client.openapi.models.V1CronJob;
import io.kubernetes.client.openapi.models.V1DaemonSet;
import io.kubernetes.client.openapi.models.V1Deployment;
import io.kubernetes.client.openapi.models.V1Ingress;
import io.kubernetes.client.openapi.models.V1Job;
import io.kubernetes.client.openapi.models.V1Pod;
import io.kubernetes.client.openapi.models.V1ReplicaSet;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.openapi.models.V1Service;
import io.kubernetes.client.openapi.models.V1StatefulSet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class KubernetesClusterInventory {
    final List<String> namespaces = new ArrayList<>();
    final List<V1Secret> secrets = new ArrayList<>();
    final List<V1Ingress> ingresses = new ArrayList<>();
    final List<V1Service> services = new ArrayList<>();
    final List<V1Pod> pods = new ArrayList<>();
    final List<V1Deployment> deployments = new ArrayList<>();
    final List<V1ReplicaSet> replicaSets = new ArrayList<>();
    final List<V1StatefulSet> statefulSets = new ArrayList<>();
    final List<V1DaemonSet> daemonSets = new ArrayList<>();
    final List<V1Job> jobs = new ArrayList<>();
    final List<V1CronJob> cronJobs = new ArrayList<>();
    final List<KubernetesCertificateUsageCandidate> customResourceUsages = new ArrayList<>();
    final List<KubernetesParsedCertificate> inlineCertificates = new ArrayList<>();
    final Set<String> installedCustomResources = new LinkedHashSet<>();
    final Map<String, Set<String>> servedCustomResourceVersions = new LinkedHashMap<>();
    boolean customResourceCatalogComplete;
    /** API discovery answers keyed by plural.group/version: whether the API server serves it. */
    final Map<String, Boolean> servedByApiDiscovery = new LinkedHashMap<>();
    final Set<String> unreadableResourceTypes = new LinkedHashSet<>();
    final List<String> warnings = new ArrayList<>();
    /** Namespaces whose TLS Secrets could not be listed; their certificates were not seen. */
    final List<com.certping.agent.model.message.DiscoveryFailedScope> failedScopes = new ArrayList<>();

    boolean usageComplete() {
        return unreadableResourceTypes.isEmpty();
    }
}
