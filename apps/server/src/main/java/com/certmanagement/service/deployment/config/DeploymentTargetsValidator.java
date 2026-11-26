// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;

import java.util.Set;

/**
 * Per-provider strategy for validating a {@code targets} JSON payload submitted via
 * the deployment-target add/edit endpoints.
 *
 * <p>Each implementation owns one or more {@link TargetType}s and enforces that the
 * requested targets are valid against the credential's scope (e.g., listener ARNs ⊆
 * {@code allowedLoadBalancerArns}, namespaces ⊆ {@code allowedNamespaces}, etc.).
 */
public interface DeploymentTargetsValidator {

    /** Target types this validator handles. The registry rejects overlapping registrations. */
    Set<TargetType> supportedTargetTypes();

    /**
     * Validate the requested targets payload against the credential's scope.
     * Throws {@link com.certmanagement.exception.BadRequestException} on failure.
     *
     * @param requestedTargets JSON submitted by the client (the {@code targets} object)
     * @param credential       the deployment credential row (provides scope via configJson)
     * @return a normalized targets JsonNode to persist (typically the same as input,
     *         optionally re-ordered/canonicalized)
     */
    JsonNode validate(JsonNode requestedTargets, CredentialReferenceEntity credential);
}
