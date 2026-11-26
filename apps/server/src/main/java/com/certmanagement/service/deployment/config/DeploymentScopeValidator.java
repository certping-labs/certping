// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config;

import com.certmanagement.messaging.model.TargetType;
import tools.jackson.databind.JsonNode;

import java.util.Set;

/**
 * Per-provider strategy for validating the {@code configJson} (= credential scope) submitted via
 * {@code POST /api/v1/credentials/deployment} or {@code PUT /api/v1/credentials/{credXref}}.
 *
 * <p>Each implementation owns one or more {@link TargetType}s and enforces field-presence,
 * format, and inter-field constraints on the credential-wide scope before it's persisted.
 * Mirrors the agent-side {@code validateScope()} checks so operators get a 400 at register
 * time rather than a deploy-time failure.
 */
public interface DeploymentScopeValidator {

    /** Target types this validator handles. The registry rejects overlapping registrations. */
    Set<TargetType> supportedTargetTypes();

    /**
     * Validate the credential scope payload.
     * Throws {@link com.certmanagement.exception.BadRequestException} on failure with a
     * field-specific message.
     *
     * @param configJson JSON submitted by the client (the {@code configJson} object). Never null —
     *                   the registry caller short-circuits null/blank before reaching the validator.
     */
    void validate(JsonNode configJson);
}
