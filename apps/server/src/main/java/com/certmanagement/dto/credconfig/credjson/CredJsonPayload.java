// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson;

/**
 * Marker for a typed credential payload mirror of an agent-side credential model.
 * Implementations are JSON-shape-compatible with the agent's reader so the server can
 * validate user-supplied credJson against a typed DTO and then serialize the typed instance
 * for the secret store write — stripping any unknown fields the UI might have sent.
 *
 * <p>The stored secret is always JSON, for every provider.
 */
public interface CredJsonPayload {
}
