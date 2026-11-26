// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.integrations.secret.agent.local;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ResourceNotFoundException;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;

/**
 * {@code certping.agent-secret-store.provider=LOCAL}: agent secrets as encrypted files in a
 * directory the server shares with the bundled agent. For single-server installs with no cloud
 * secret manager; an agent on another machine needs a cloud store instead.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "certping.agent-secret-store.provider", havingValue = "LOCAL")
public class LocalAgentSecretDriver implements AgentSecretStore {

    private final LocalSecretFiles files;
    private final String ownPrefix;

    @Autowired
    public LocalAgentSecretDriver(AgentSecretStoreProperties properties) {
        this(new LocalSecretFiles(Path.of(properties.getLocal().getDirectory()), properties.getLocal().getKey()),
                properties.getLocal().getOwnPrefix());
        log.info("LocalAgentSecretDriver ready: directory={}, prefix={}",
                properties.getLocal().getDirectory(), ownPrefix);
    }

    LocalAgentSecretDriver(LocalSecretFiles files, String ownPrefix) {
        this.files = files;
        this.ownPrefix = ownPrefix == null ? "" : ownPrefix;
    }

    @Override
    public AgentSecretStoreProvider provider() {
        return AgentSecretStoreProvider.LOCAL;
    }

    @Override
    public String create(String name, String value) {
        String full = ownName(name);
        write(full, value);
        return LocalSecretFiles.handleOf(full);
    }

    @Override
    public String read(String handle) {
        String name = requireHandle(handle);
        try {
            return files.read(name).orElseThrow(
                    () -> new ResourceNotFoundException("Agent secret not found at handle: " + handle));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read agent secret " + handle, e);
        }
    }

    @Override
    public String update(String handle, String value) {
        String name = requireHandle(handle);
        if (!isOwnedByThisCertManager(handle)) {
            throw new BadRequestException("Refusing to update secret at foreign LOCAL handle: " + handle);
        }
        if (!files.exists(name)) {
            throw new ResourceNotFoundException("Agent secret not found at handle: " + handle);
        }
        write(name, value);
        return handle;
    }

    @Override
    public void deleteIfOwned(String handle) {
        if (!isOwnedByThisCertManager(handle)) {
            return;
        }
        try {
            if (files.delete(LocalSecretFiles.nameOf(handle))) {
                log.info("Deleted agent LOCAL secret: handle={}", handle);
            }
        } catch (IOException e) {
            log.warn("LOCAL delete failed for handle={}: {}", handle, e.getMessage());
        }
    }

    @Override
    public boolean isOwnedByThisCertManager(String handle) {
        return LocalSecretFiles.isHandle(handle) && LocalSecretFiles.nameOf(handle).startsWith(ownPrefix);
    }

    @Override
    public boolean isAgentCertificateHandle(String handle, String certificateXref) {
        return certificateXref != null && LocalSecretFiles.isHandle(handle)
                && LocalSecretFiles.nameOf(handle).equals(ownPrefix + certificateXref);
    }

    @Override
    public String handleFor(String name) {
        return LocalSecretFiles.handleOf(ownName(name));
    }

    private String ownName(String name) {
        String full = ownPrefix + (name == null ? "" : name);
        if (name == null || name.isEmpty() || !LocalSecretFiles.isName(full)) {
            throw new BadRequestException("Secret name must match [A-Za-z0-9_-], got: " + name);
        }
        return full;
    }

    private void write(String name, String value) {
        try {
            files.write(name, value);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write agent secret " + name, e);
        }
    }

    private static String requireHandle(String handle) {
        if (!LocalSecretFiles.isHandle(handle)) {
            throw new BadRequestException("Not a LOCAL secret handle: " + handle);
        }
        return LocalSecretFiles.nameOf(handle);
    }
}
