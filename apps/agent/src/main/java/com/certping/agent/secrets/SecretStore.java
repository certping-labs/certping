// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

/** Single-provider port for the agent's cert-lifecycle secret store. Handles are opaque. */
public interface SecretStore {

    String read(String handle);

    String create(String name, String value);

    /** Returns the handle to use for subsequent reads — providers that version secrets return a new handle. */
    String update(String handle, String value);

    void delete(String handle);

    /** Guards checkpoint-purge from deleting inbound customer handles. */
    boolean isOwnedByThisAgent(String handle);

    /** Handle that {@link #create}(name, ...) would produce, without a round-trip. */
    String handleFor(String name);

    SecretStoreProvider provider();
}
