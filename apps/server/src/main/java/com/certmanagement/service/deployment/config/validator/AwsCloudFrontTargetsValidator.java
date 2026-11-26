// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.messaging.model.TargetType;
import com.certmanagement.service.deployment.config.DeploymentTargetsValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Validates AWS CloudFront deployment targets — always empty.
 *
 * <p>CloudFront uses one distribution per credential (stored in scope). There are no
 * per-cert target fields to select or validate, so this validator always returns an
 * empty JSON object.
 */
@Component
@RequiredArgsConstructor
public class AwsCloudFrontTargetsValidator implements DeploymentTargetsValidator {

    private static final Set<TargetType> SUPPORTED = Set.of(TargetType.AWS_CLOUDFRONT);

    private final ObjectMapper objectMapper;

    @Override
    public Set<TargetType> supportedTargetTypes() {
        return SUPPORTED;
    }

    @Override
    public JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential) {
        return objectMapper.createObjectNode();
    }
}
