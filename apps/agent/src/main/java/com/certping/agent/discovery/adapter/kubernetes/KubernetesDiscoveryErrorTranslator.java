// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import io.kubernetes.client.openapi.ApiException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class KubernetesDiscoveryErrorTranslator {

    private KubernetesDiscoveryErrorTranslator() {
    }

    static RuntimeException translate(String errorCode, String operation, ApiException e) {
        String responseBody = e.getResponseBody();
        log.debug("Kubernetes discovery API operation failed operation={} statusCode={} responseBodyPresent={} responseBodyChars={}",
                operation,
                e.getCode(),
                responseBody != null && !responseBody.isBlank(),
                responseBody == null ? 0 : responseBody.length());
        String message = safeMessage(errorCode, e.getCode());
        if (e.getCode() == 400 || e.getCode() == 401 || e.getCode() == 403 || e.getCode() == 404) {
            return new PermanentAgentException(errorCode, message, e);
        }
        return new TransientAgentException(errorCode, message, e);
    }

    static boolean isForbidden(ApiException e) {
        return e.getCode() == 401 || e.getCode() == 403;
    }

    static boolean isNotFound(ApiException e) {
        return e.getCode() == 404;
    }

    private static String safeMessage(String errorCode, int statusCode) {
        return switch (errorCode) {
            case "DISCOVERY_K8S_NAMESPACE_LIST_DENIED" ->
                    "Kubernetes certificate discovery could not list namespaces (HTTP " + statusCode
                            + "). Grant the discovery identity permission to list Namespaces cluster-wide, "
                            + "or send explicit namespaces.";
            case "DISCOVERY_K8S_SECRET_LIST_FAILED" ->
                    "Kubernetes certificate discovery could not list TLS Secrets (HTTP " + statusCode
                            + "). Grant the discovery identity permission to list Secrets in the requested namespace(s).";
            default -> accessDeniedMessage(statusCode);
        };
    }

    private static String accessDeniedMessage(int statusCode) {
        if (statusCode == 401 || statusCode == 403) {
            return "Kubernetes certificate discovery was denied by Kubernetes API authorization (HTTP "
                    + statusCode + "). Grant the discovery identity read access to the requested Kubernetes resources.";
        }
        return "Kubernetes certificate discovery API request failed (HTTP " + statusCode + ")";
    }
}
