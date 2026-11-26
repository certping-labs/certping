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
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Validates {@code F5_BIGIP} targets.
 *
 * <p>Optional {@code certBaseName} pins the F5 SSL object base name on first deploy
 * (suffixed with {@code _v{n}} per rotation). When omitted, the agent auto-derives from
 * cert xref / domain. Locked across rotations by stripping the version suffix from the
 * prior {@code result.certName} — operator edits have no effect after first deploy.
 */
@Component
@RequiredArgsConstructor
public class F5TargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.F5_BIGIP);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        ObjectNode root = objectMapper.createObjectNode();
        if (requestedTargets == null || requestedTargets.isNull()) {
            return root;
        }
        if (!requestedTargets.isObject()) {
            throw new BadRequestException("F5 BIG-IP targets must be a JSON object");
        }
        JsonNode certBase = requestedTargets.get("certBaseName");
        if (certBase != null && !certBase.isNull()) {
            if (!certBase.isString()) {
                throw new BadRequestException("F5 BIG-IP targets.certBaseName must be a string");
            }
            String value = certBase.asString().trim();
            if (!value.isEmpty()) {
                root.put("certBaseName", value);
            }
        }
        return root;
    }
}
