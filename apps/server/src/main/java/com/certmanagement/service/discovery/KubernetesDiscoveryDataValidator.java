// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.discovery;

import com.certmanagement.messaging.model.KubernetesDiscoveryData;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class KubernetesDiscoveryDataValidator {

    private final ObjectMapper objectMapper;

    public KubernetesDiscoveryData validateAndConvert(JsonNode providerData) {
        if (providerData == null || !providerData.isObject()) {
            throw invalid("kubernetesData must be a JSON object");
        }
        KubernetesDiscoveryData data;
        try {
            data = objectMapper.treeToValue(providerData, KubernetesDiscoveryData.class);
        } catch (Exception exception) {
            throw invalid("kubernetesData could not be parsed", exception);
        }
        validate(data);
        return data;
    }

    private void validate(KubernetesDiscoveryData data) {
        requireText(data.clusterName(), "clusterName");
        require(data.usageComplete(), "usageComplete");
        require(data.impactComplete(), "impactComplete");
        requireList(data.unreadableResourceTypes(), "unreadableResourceTypes");
        validateSource(require(data.source(), "source"));
        requireList(data.usages(), "usages").forEach(this::validateUsage);
        validateImpact(require(data.impact(), "impact"));
        requireList(data.warnings(), "warnings");
    }

    private void validateSource(KubernetesDiscoveryData.Source source) {
        requireText(source.apiVersion(), "source.apiVersion");
        requireText(source.kind(), "source.kind");
        requireText(source.namespace(), "source.namespace");
        requireText(source.name(), "source.name");
        requireText(source.type(), "source.type");
        requireText(source.fingerprintSha256(), "source.fingerprintSha256");
    }

    private void validateUsage(KubernetesDiscoveryData.Usage usage) {
        requireText(usage.apiVersion(), "usages[].apiVersion");
        requireText(usage.kind(), "usages[].kind");
        requireText(usage.namespace(), "usages[].namespace");
        requireText(usage.name(), "usages[].name");
        requireText(usage.fieldPath(), "usages[].fieldPath");
        requireText(usage.usageType(), "usages[].usageType");
        requireList(usage.hostnames(), "usages[].hostnames");
        requireList(usage.backendServices(), "usages[].backendServices")
                .forEach(this::validateBackendService);
        requireList(usage.affectedWorkloads(), "usages[].affectedWorkloads")
                .forEach(this::validateAffectedWorkload);
        requireText(usage.confidence(), "usages[].confidence");
    }

    private void validateBackendService(KubernetesDiscoveryData.BackendService service) {
        requireText(service.namespace(), "usages[].backendServices[].namespace");
        requireText(service.name(), "usages[].backendServices[].name");
    }

    private void validateAffectedWorkload(KubernetesDiscoveryData.AffectedWorkload workload) {
        requireText(workload.apiVersion(), "usages[].affectedWorkloads[].apiVersion");
        requireText(workload.kind(), "usages[].affectedWorkloads[].kind");
        requireText(workload.namespace(), "usages[].affectedWorkloads[].namespace");
        requireText(workload.name(), "usages[].affectedWorkloads[].name");
        requireList(workload.containers(), "usages[].affectedWorkloads[].containers");
        requireText(workload.referencePath(), "usages[].affectedWorkloads[].referencePath");
    }

    private void validateImpact(KubernetesDiscoveryData.Impact impact) {
        require(impact.externallyServed(), "impact.externallyServed");
        require(impact.directlyMountedByWorkloads(), "impact.directlyMountedByWorkloads");
        requireList(impact.affectedHostnames(), "impact.affectedHostnames");
        requireList(impact.affectedServices(), "impact.affectedServices");
        requireList(impact.affectedWorkloads(), "impact.affectedWorkloads");
        requireText(impact.summary(), "impact.summary");
    }

    private <T> T require(T value, String field) {
        if (value == null) {
            throw invalid(field + " is required");
        }
        return value;
    }

    private <T> List<T> requireList(List<T> value, String field) {
        return require(value, field);
    }

    private void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw invalid(field + " must not be blank");
        }
    }

    private IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException("Invalid Kubernetes discovery response: " + message);
    }

    private IllegalArgumentException invalid(String message, Exception cause) {
        return new IllegalArgumentException("Invalid Kubernetes discovery response: " + message, cause);
    }
}
