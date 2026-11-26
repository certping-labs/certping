// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.azure;

import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Slf4j
final class AzureKvCertificateNameSupport {

    private AzureKvCertificateNameSupport() {}

    static String resolveCertificateName(ObjectMapper objectMapper, String domain, String certXref, String configJson) {
        if (configJson != null && !configJson.isBlank()) {
            String certName = parseCertificateName(objectMapper, configJson);
            if (certName == null || certName.isBlank()) {
                throw new PermanentAgentException("DEPLOY_CERT_NAME_INVALID",
                        "configJson present but missing certificateName for domain=" + domain + " xref=" + certXref);
            }
            return certName;
        }

        String fromDomain = CertificateIdentityUtils.toAzureKvCertificateName(domain);
        if (fromDomain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CERT_NAME_INVALID",
                    "Unable to derive Azure KV certificate name from domain: '" + domain + "'");
        }
        return fromDomain;
    }

    static String parseCertificateName(ObjectMapper objectMapper, String configJson) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> map = objectMapper.readValue(configJson, Map.class);
            return map.get("certificateName");
        } catch (Exception e) {
            log.warn("Failed to parse certificateName from configJson='{}': {}", configJson, e.getMessage());
            return null;
        }
    }

    static String toCertificateNameJson(ObjectMapper objectMapper, String certName) {
        try {
            return objectMapper.writeValueAsString(Map.of("certificateName", certName));
        } catch (Exception e) {
            return "{\"certificateName\":\"" + certName + "\"}";
        }
    }
}

