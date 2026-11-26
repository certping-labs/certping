// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.model.message.DiscoveredCertEntry;
import com.certping.agent.model.message.KubernetesCertificateData;
import com.certping.agent.model.message.KubernetesCertificateSource;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Secret;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

record KubernetesParsedCertificate(
        String clusterName,
        String namespace,
        String name,
        String usageLookupKey,
        String resourceId,
        String certType,
        KubernetesCertificateSource source,
        X509Certificate certificate,
        List<String> warnings) {

    static KubernetesParsedCertificate fromSecret(String clusterName,
            V1Secret secret,
            X509Certificate certificate,
            String fingerprintSha256,
            List<String> warnings) {
        V1ObjectMeta metadata = secret.getMetadata();
        String namespace = metadata != null ? metadata.getNamespace() : null;
        String name = metadata != null ? metadata.getName() : null;
        String resourceId = "k8s://" + clusterName + "/" + namespace + "/secrets/" + name;
        KubernetesCertificateSource source = KubernetesCertificateSource.builder()
                .apiVersion("v1")
                .kind("Secret")
                .namespace(namespace)
                .name(name)
                .uid(metadata != null ? metadata.getUid() : null)
                .resourceVersion(metadata != null ? metadata.getResourceVersion() : null)
                .type(secret.getType())
                .fingerprintSha256(fingerprintSha256)
                .build();
        return new KubernetesParsedCertificate(
                clusterName,
                namespace,
                name,
                usageLookupKey("Secret", namespace, name),
                resourceId,
                "KUBERNETES_TLS_SECRET",
                source,
                certificate,
                new ArrayList<>(warnings));
    }

    static KubernetesParsedCertificate fromInlineCustomResource(String clusterName,
            String apiVersion,
            String kind,
            String namespace,
            String name,
            String uid,
            String resourceVersion,
            String fieldPath,
            X509Certificate certificate,
            String fingerprintSha256,
            List<String> warnings) {
        String resourceId = "k8s://" + clusterName + "/" + namespace + "/"
                + kind.toLowerCase(java.util.Locale.ROOT) + "s/" + name + "/" + fieldPath;
        KubernetesCertificateSource source = KubernetesCertificateSource.builder()
                .apiVersion(apiVersion)
                .kind(kind)
                .namespace(namespace)
                .name(name)
                .uid(uid)
                .resourceVersion(resourceVersion)
                .type(fieldPath)
                .fingerprintSha256(fingerprintSha256)
                .build();
        return new KubernetesParsedCertificate(
                clusterName,
                namespace,
                name,
                usageLookupKey(kind, namespace, name),
                resourceId,
                "KUBERNETES_INLINE_CERT",
                source,
                certificate,
                new ArrayList<>(warnings));
    }

    static String usageLookupKey(String sourceKind, String namespace, String name) {
        return sourceKind + "/" + namespace + "/" + name;
    }

    DiscoveredCertEntry toEntry(KubernetesCertificateData kubernetesData,
            KubernetesCertificateMetadata metadata,
            List<String> inUseBy) {
        return DiscoveredCertEntry.builder()
                .resourceId(resourceId)
                .domain(metadata.domain())
                .keyAlgorithm(metadata.keyAlgorithm())
                .signatureAlgorithm(metadata.signatureAlgorithm())
                .notBefore(metadata.notBefore())
                .notAfter(metadata.notAfter())
                .issuer(metadata.issuer())
                .serialNumber(metadata.serialNumber())
                .certStatus(metadata.certStatus())
                .inUseBy(inUseBy)
                .subjectDn(metadata.subjectDn())
                .sanDomains(metadata.sanDomains().isEmpty() ? null : metadata.sanDomains())
                .keyUsage(metadata.keyUsage())
                .extendedKeyUsage(metadata.extendedKeyUsage())
                .certType(certType)
                .kubernetesData(kubernetesData)
                .build();
    }
}
