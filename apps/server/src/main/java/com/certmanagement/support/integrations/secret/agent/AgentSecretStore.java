// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent;

/**
 * Provider-neutral port for the agent-facing secret store — writes credJson payloads and
 * hands back a handle the agent can dereference at cert-lifecycle time.
 *
 * <p>The integration secrets (webhook URLs, ServiceNow and PagerDuty keys) are kept in the same
 * store through {@link com.certmanagement.support.integrations.secret.SecretStore}; only the
 * server reads those.
 *
 * <p>Shape mirrors the agent's {@code com.certping.agent.secrets.SecretStore} so provider-neutral
 * plumbing on both sides speaks the same vocabulary. Handles are opaque strings whose exact shape
 * (KV URI / SM ARN / SM resource name) is a private detail of the active driver.
 */
public interface AgentSecretStore {

    /**
     * Writes {@code value} verbatim at a deterministic address derived from {@code name}.
     * Idempotent — overwrites if the secret already exists. Returns the handle to persist so the
     * agent can read this same value later.
     */
    String create(String name, String value);

    /**
     * Reads the current value at {@code handle}. Provider-neutral errors propagate as
     * {@link IllegalArgumentException} for bad handles, {@link
     * com.certmanagement.exception.ResourceNotFoundException} for missing secrets, {@link
     * AgentSecretGoneException} for a secret whose value can never be read again (destroyed or
     * disabled version, scheduled deletion), and unclassified failures as {@link IllegalStateException}.
     */
    String read(String handle);

    /**
     * Overwrites the value at an existing {@code handle} — used by credJson rotation so the
     * downstream agent handle stays stable across rotations. Returns the refreshed handle;
     * providers that version secrets (AWS SM, GCP SM) return a new version-specific handle. Azure
     * returns the same handle unchanged.
     */
    String update(String handle, String value);

    /**
     * Deletes the secret behind {@code handle} — only if this server owns it. Foreign
     * handles (a customer's pre-existing KV URI in mixed-mode setups) are a no-op. Missing
     * secrets are a no-op (idempotent).
     */
    void deleteIfOwned(String handle);

    /**
     * True when {@code handle} points at a secret this server created. Guards deletion
     * paths from purging customer-owned secrets in mixed-mode setups.
     */
    boolean isOwnedByThisCertManager(String handle);

    /**
     * True when {@code handle} addresses, inside the store this server is configured for, the
     * secret the agent writes for certificate {@code certificateXref} (named after the xref).
     *
     * <p>Readers of certificate material call this before {@link #read}: the store also holds
     * organisation credential secrets, and some drivers resolve only the secret name from a handle,
     * so a handle that names any other secret must never be dereferenced on a certificate's behalf.
     * Pure string check; no round-trip.
     */
    boolean isAgentCertificateHandle(String handle, String certificateXref);

    /** Deterministic handle that {@link #create}({@code name}, …) would produce, without a round-trip. */
    String handleFor(String name);

    /** Which provider this instance is running against. */
    AgentSecretStoreProvider provider();

    /**
     * True when this driver holds enough config to actually serve reads/writes.
     *
     * <p>Defaults to {@code true} — drivers that fail hard in their {@code init()} on missing
     * config (AWS, GCP) either wire fully or the pod won't start, so bean presence is the same
     * as readiness. Drivers that log-and-continue on missing config (Azure, on servers where
     * the credJson path is never invoked) override this to reflect their real state so upstream
     * callers can decline gracefully instead of throwing {@code IllegalStateException} at IO time.
     */
    default boolean isReady() {
        return true;
    }
}
