// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

import com.certping.agent.exception.PermanentAgentException;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** This agent's own vault, in memory: handles are {@link #VAULT}{@code /secrets/{name}}, writes overwrite. */
public final class InMemorySecretStore implements SecretStore {

    public static final String VAULT = "https://kv.vault.azure.net";

    private final Map<String, String> secrets = new ConcurrentHashMap<>();

    @Override
    public String read(String handle) {
        String value = secrets.get(nameOf(handle));
        if (value == null) {
            throw new PermanentAgentException("KV_SECRET_NOT_FOUND", "Secret not found at handle: " + handle);
        }
        return value;
    }

    @Override
    public String create(String name, String value) {
        secrets.put(name, value);
        return handleFor(name);
    }

    @Override
    public String update(String handle, String value) {
        secrets.put(nameOf(handle), value);
        return handle;
    }

    @Override
    public void delete(String handle) {
        if (secrets.remove(nameOf(handle)) == null) {
            throw new PermanentAgentException("KV_SECRET_NOT_FOUND", "Secret not found at handle: " + handle);
        }
    }

    @Override
    public boolean isOwnedByThisAgent(String handle) {
        return handle != null && handle.startsWith(VAULT + "/secrets/");
    }

    @Override
    public String handleFor(String name) {
        return VAULT + "/secrets/" + name;
    }

    @Override
    public SecretStoreProvider provider() {
        return SecretStoreProvider.AZURE_KV;
    }

    /** The value stored under {@code name}, or null. */
    public String get(String name) {
        return secrets.get(name);
    }

    public boolean contains(String name) {
        return secrets.containsKey(name);
    }

    private static String nameOf(String handle) {
        return handle.substring(handle.indexOf("/secrets/") + "/secrets/".length()).split("/")[0];
    }
}
