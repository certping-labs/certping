// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validates {@code AZURE_KV} targets.
 *
 * <p>Shape: {@code {"certificateName": "my-cert-name"}} (optional).
 * The vault URI lives in the credential scope ({@code configJson.vaultUri}), not in targets.
 *
 * <p>{@code certificateName} is optional — if omitted, the agent auto-derives the KV cert name
 * from the cert's primary domain. If supplied, it locks the name across rotations and must
 * match the Azure KV format (1–127 alphanumeric/hyphen).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AzureKvTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AZURE_KV);
    private static final Pattern CERT_NAME = Pattern.compile("^[a-zA-Z0-9-]{1,127}$");

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() { return SUPPORTED; }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        ObjectNode normalized = objectMapper.createObjectNode();
        if (requestedTargets == null || requestedTargets.isNull()) {
            return normalized;
        }
        if (!requestedTargets.isObject()) {
            throw new BadRequestException("Azure KV targets must be a JSON object");
        }
        JsonNode certNameNode = requestedTargets.get("certificateName");
        if (certNameNode == null || certNameNode.isNull()) {
            return normalized;
        }
        if (!certNameNode.isString()) {
            throw new BadRequestException("Azure KV targets.certificateName must be a string");
        }
        String certName = certNameNode.asString().trim();
        if (certName.isEmpty()) {
            return normalized;
        }
        if (!CERT_NAME.matcher(certName).matches()) {
            throw new BadRequestException(
                    "Azure KV certificateName must be 1-127 alphanumeric or hyphen characters: '" + certName + "'");
        }
        normalized.put("certificateName", certName);
        return normalized;
    }
}
