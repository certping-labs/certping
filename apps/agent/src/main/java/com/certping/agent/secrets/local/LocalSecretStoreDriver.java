// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.local;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.secrets.SecretStoreDriver;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Path;

/**
 * {@code agent.secret-store.provider=LOCAL}: encrypted files in a directory shared with the
 * server. Meant for a single-server install where the bundled agent and the server mount the same
 * volume. An agent on another machine should use a cloud secret manager instead.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "agent.secret-store.provider", havingValue = "LOCAL")
public class LocalSecretStoreDriver implements SecretStoreDriver {

    private final LocalSecretFiles files;
    private final String ownPrefix;

    @Autowired
    public LocalSecretStoreDriver(SecretStoreProperties properties) {
        this(new LocalSecretFiles(Path.of(properties.getLocal().getDirectory()), properties.getLocal().getKey()),
                properties.getLocal().getOwnPrefix());
        log.info("LocalSecretStoreDriver ready: directory={}, prefix={}",
                properties.getLocal().getDirectory(), ownPrefix);
    }

    LocalSecretStoreDriver(LocalSecretFiles files, String ownPrefix) {
        this.files = files;
        this.ownPrefix = ownPrefix == null ? "" : ownPrefix;
    }

    @Override
    public SecretStoreProvider provider() {
        return SecretStoreProvider.LOCAL;
    }

    @Override
    public boolean parsesHandle(String handle) {
        return LocalSecretFiles.isHandle(handle);
    }

    @Override
    public void assertValidName(String name) {
        if (!LocalSecretFiles.isName(ownPrefix + (name == null ? "" : name)) || name == null || name.isEmpty()) {
            throw new PermanentAgentException("SECRET_STORE_NAME_INVALID",
                    "Secret name must match [A-Za-z0-9_-], got: " + (name == null ? "null" : "'" + name + "'"));
        }
    }

    @Override
    public String read(String handle) {
        String name = requireHandle(handle);
        if (!isOwnedByThisAgent(handle)) {
            throw new PermanentAgentException("SECRET_STORE_FOREIGN_HANDLE",
                    "Refusing to read a secret this agent does not own: " + handle
                            + " (LOCAL secret names must start with '" + ownPrefix + "')");
        }
        try {
            return files.read(name).orElseThrow(() -> new PermanentAgentException("LOCAL_SECRET_NOT_FOUND",
                    "Secret not found at handle: " + handle));
        } catch (IOException e) {
            throw new TransientAgentException("LOCAL_SECRET_READ_FAILED",
                    "Failed to read secret " + handle + ": " + e.getMessage(), e);
        } catch (IllegalStateException e) {
            throw new PermanentAgentException("LOCAL_SECRET_UNREADABLE", e.getMessage(), e);
        }
    }

    @Override
    public String create(String name, String value) {
        assertValidName(name);
        String full = ownPrefix + name;
        write(full, value);
        return LocalSecretFiles.handleOf(full);
    }

    @Override
    public String update(String handle, String value) {
        String name = requireHandle(handle);
        if (!isOwnedByThisAgent(handle)) {
            throw new PermanentAgentException("SECRET_STORE_FOREIGN_HANDLE",
                    "Refusing to update a secret this agent does not own: " + handle);
        }
        write(name, value);
        return handle;
    }

    @Override
    public void delete(String handle) {
        if (!parsesHandle(handle) || !isOwnedByThisAgent(handle)) {
            return;
        }
        try {
            files.delete(LocalSecretFiles.nameOf(handle));
        } catch (IOException e) {
            log.warn("LOCAL secret delete failed for handle={}: {}", handle, e.getMessage());
        }
    }

    @Override
    public boolean isOwnedByThisAgent(String handle) {
        return parsesHandle(handle) && LocalSecretFiles.nameOf(handle).startsWith(ownPrefix);
    }

    @Override
    public String handleFor(String name) {
        assertValidName(name);
        return LocalSecretFiles.handleOf(ownPrefix + name);
    }

    private void write(String name, String value) {
        try {
            files.write(name, value);
        } catch (IOException e) {
            throw new TransientAgentException("LOCAL_SECRET_WRITE_FAILED",
                    "Failed to write secret " + name + ": " + e.getMessage(), e);
        }
    }

    private String requireHandle(String handle) {
        if (!parsesHandle(handle)) {
            throw new PermanentAgentException("SECRET_STORE_HANDLE_INVALID", "Not a LOCAL secret handle: " + handle);
        }
        return LocalSecretFiles.nameOf(handle);
    }
}
