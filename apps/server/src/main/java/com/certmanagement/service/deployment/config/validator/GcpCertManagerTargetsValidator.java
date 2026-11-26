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

/**
 * Validates {@code GCP_CERT_MANAGER} deployment targets.
 *
 * <p>Optional {@code certificateName} pins the GCP Certificate resource id used on first
 * deploy (Azure-KV style). When omitted, the agent auto-derives a versioned id. Either
 * way, the result locks the resource name across rotations — operator edits have no effect
 * after first deploy.
 *
 * <p>Hostname binding on the certificate map is automatic from the cert's CN+SANs at deploy
 * time; no per-hostname operator config lives here.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class GcpCertManagerTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.GCP_CERT_MANAGER);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() { return SUPPORTED; }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        ObjectNode normalized = objectMapper.createObjectNode();
        if (requestedTargets == null || !requestedTargets.isObject()) {
            return normalized;
        }
        JsonNode certNameNode = requestedTargets.get("certificateName");
        if (certNameNode != null && !certNameNode.isNull()) {
            if (!certNameNode.isString()) {
                throw new BadRequestException("GCP Cert Manager targets.certificateName must be a string");
            }
            String certificateName = certNameNode.asString().trim();
            if (!certificateName.isEmpty()) {
                normalized.put("certificateName", certificateName);
            }
        }
        return normalized;
    }
}
