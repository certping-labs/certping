// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record KubernetesDiscoveryData(
        String clusterName,
        Boolean usageComplete,
        Boolean impactComplete,
        List<String> unreadableResourceTypes,
        Source source,
        List<Usage> usages,
        Impact impact,
        List<String> warnings) implements ProviderDiscoveryData {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Source(
            String apiVersion,
            String kind,
            String namespace,
            String name,
            String uid,
            String resourceVersion,
            String type,
            String fingerprintSha256) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Usage(
            String apiVersion,
            String kind,
            String namespace,
            String name,
            String uid,
            String fieldPath,
            String usageType,
            List<String> hostnames,
            List<BackendService> backendServices,
            List<AffectedWorkload> affectedWorkloads,
            String confidence) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record BackendService(
            String namespace,
            String name,
            String portName,
            Integer portNumber) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AffectedWorkload(
            String apiVersion,
            String kind,
            String namespace,
            String name,
            List<String> containers,
            String referencePath) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Impact(
            Boolean externallyServed,
            Boolean directlyMountedByWorkloads,
            List<String> affectedHostnames,
            List<String> affectedServices,
            List<String> affectedWorkloads,
            String summary) {
    }
}
