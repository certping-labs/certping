// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets.local;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.secrets.SecretStoreProperties;
import com.certping.agent.secrets.SecretStoreProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalSecretStoreDriverTest {

    private static final String KEY = Base64.getEncoder().encodeToString(new byte[32]);
    private static final String OTHER_KEY = Base64.getEncoder().encodeToString("x".repeat(32).getBytes());

    @TempDir
    Path dir;

    private LocalSecretStoreDriver driver(String key) {
        SecretStoreProperties properties = new SecretStoreProperties();
        properties.getLocal().setDirectory(dir.toString());
        properties.getLocal().setKey(key);
        return new LocalSecretStoreDriver(properties);
    }

    @Test
    void storesEncryptedAndReadsBack() throws Exception {
        LocalSecretStoreDriver driver = driver(KEY);
        String handle = driver.create("dns-cred-1", "{\"token\":\"s3cret\"}");

        assertThat(handle).isEqualTo("local:certping-dns-cred-1").isEqualTo(driver.handleFor("dns-cred-1"));
        assertThat(driver.read(handle)).isEqualTo("{\"token\":\"s3cret\"}");
        assertThat(Files.readString(dir.resolve("certping-dns-cred-1.secret"), java.nio.charset.StandardCharsets.ISO_8859_1))
                .doesNotContain("s3cret");
        assertThat(driver.provider()).isEqualTo(SecretStoreProvider.LOCAL);

        assertThat(driver.update(handle, "v2")).isEqualTo(handle);
        assertThat(driver.read(handle)).isEqualTo("v2");
        driver.delete(handle);
        assertThatThrownBy(() -> driver.read(handle)).isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode()).isEqualTo("LOCAL_SECRET_NOT_FOUND"));
    }

    @Test
    void handlesAndOwnership() {
        LocalSecretStoreDriver driver = driver(KEY);
        assertThat(driver.parsesHandle("local:certping-a")).isTrue();
        assertThat(driver.parsesHandle("https://kv.vault.azure.net/secrets/a")).isFalse();
        assertThat(driver.parsesHandle("local:../etc/passwd")).isFalse();
        assertThat(driver.isOwnedByThisAgent("local:certping-a")).isTrue();
        assertThat(driver.isOwnedByThisAgent("local:someone-else")).isFalse();
        assertThatThrownBy(() -> driver.update("local:someone-else", "x")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.read("nope")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.assertValidName("bad/name")).isInstanceOf(PermanentAgentException.class);
        assertThatThrownBy(() -> driver.assertValidName(null)).isInstanceOf(PermanentAgentException.class);
        driver.delete("local:someone-else");
        driver.delete("not-a-handle");
    }

    @Test
    void readRefusesASecretThisAgentDoesNotOwn() throws Exception {
        // A file outside this agent's prefix, written with the same key, must not be readable
        // just because it sits in the shared directory.
        new LocalSecretFiles(dir, KEY).write("someone-else", "foreign-value");
        LocalSecretStoreDriver driver = driver(KEY);

        assertThatThrownBy(() -> driver.read("local:someone-else")).isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("SECRET_STORE_FOREIGN_HANDLE"))
                .hasMessageNotContaining("foreign-value");
    }

    @Test
    void aDifferentKeyCannotReadAndTheErrorSaysWhy() {
        String handle = driver(KEY).create("x", "v");
        assertThatThrownBy(() -> driver(OTHER_KEY).read(handle)).isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("CERTPING_LOCAL_SECRET_KEY");
    }

    @Test
    void aRenamedFileDoesNotDecryptAsAnotherSecret() throws Exception {
        LocalSecretStoreDriver driver = driver(KEY);
        driver.create("a", "value-a");
        Files.copy(dir.resolve("certping-a.secret"), dir.resolve("certping-b.secret"));
        assertThatThrownBy(() -> driver.read("local:certping-b")).isInstanceOf(PermanentAgentException.class);
        Files.writeString(dir.resolve("certping-c.secret"), "garbage");
        assertThatThrownBy(() -> driver.read("local:certping-c")).isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void theKeyMustBe32BytesOfBase64() {
        assertThatThrownBy(() -> driver(null)).hasMessageContaining("CERTPING_LOCAL_SECRET_KEY");
        assertThatThrownBy(() -> driver("not base64!")).hasMessageContaining("base64");
        assertThatThrownBy(() -> driver(Base64.getEncoder().encodeToString(new byte[16])))
                .hasMessageContaining("32 bytes");
    }

    @Test
    void fileHelpersValidateNames() throws Exception {
        LocalSecretFiles files = new LocalSecretFiles(dir.resolve("nested"), KEY);
        assertThat(files.read("missing")).isEmpty();
        assertThat(files.exists("missing")).isFalse();
        assertThat(files.delete("missing")).isFalse();
        assertThatThrownBy(() -> files.write("../x", "v")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> LocalSecretFiles.nameOf("local:..")).isInstanceOf(IllegalArgumentException.class);
    }
}
