// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Behaviour spec every {@link SecretStoreDriver} implementation must satisfy. */
public abstract class SecretStoreContractTest {

    protected abstract SecretStoreDriver newDriver();

    protected String uniqueName(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    @Test
    void lifecycle_createReadUpdateDeleteRoundTrip() {
        SecretStoreDriver driver = newDriver();
        String name = uniqueName("contract-lifecycle");

        String handle = driver.create(name, "v1");
        assertThat(handle).isNotBlank();
        assertThat(driver.read(handle)).isEqualTo("v1");

        String updatedHandle = driver.update(handle, "v2");
        assertThat(driver.read(updatedHandle)).isEqualTo("v2");

        driver.delete(updatedHandle);

        assertThatThrownBy(() -> driver.read(updatedHandle))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void handleFor_matchesShapeOfCreatedHandle() {
        SecretStoreDriver driver = newDriver();
        String name = uniqueName("contract-handlefor");

        String predicted = driver.handleFor(name);
        assertThat(predicted).isNotBlank();
        assertThat(driver.parsesHandle(predicted)).isTrue();

        String actual = driver.create(name, "v");
        assertThat(driver.parsesHandle(actual)).isTrue();

        driver.delete(actual);
    }

    @Test
    void isOwnedByThisAgent_trueForOwnCreatedHandle() {
        SecretStoreDriver driver = newDriver();
        String name = uniqueName("contract-owned");
        String handle = driver.create(name, "v");

        assertThat(driver.isOwnedByThisAgent(handle)).isTrue();

        driver.delete(handle);
    }

    @Test
    void isOwnedByThisAgent_falseForForeignHandle() {
        SecretStoreDriver driver = newDriver();
        String foreign = foreignHandleExample();
        assertThat(driver.parsesHandle(foreign)).isTrue();
        assertThat(driver.isOwnedByThisAgent(foreign)).isFalse();
    }

    /** A parseable handle for this provider that does NOT belong to the agent's own store. */
    protected abstract String foreignHandleExample();

    @Test
    void parsesHandle_rejectsObviouslyInvalid() {
        SecretStoreDriver driver = newDriver();
        assertThat(driver.parsesHandle(null)).isFalse();
        assertThat(driver.parsesHandle("")).isFalse();
        assertThat(driver.parsesHandle("   ")).isFalse();
        assertThat(driver.parsesHandle("not-a-handle")).isFalse();
    }

    @Test
    void assertValidName_rejectsCharsOutsideCommonSubset() {
        SecretStoreDriver driver = newDriver();
        assertThatThrownBy(() -> driver.assertValidName(""))
                .as("empty name rejected")
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> driver.assertValidName("has spaces"))
                .as("spaces rejected")
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> driver.assertValidName("has/slash"))
                .as("slash rejected in the common subset")
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void assertValidName_acceptsCommonSubset() {
        SecretStoreDriver driver = newDriver();
        assertThatCode(() -> driver.assertValidName("cert-2001"))
                .doesNotThrowAnyException();
        assertThatCode(() -> driver.assertValidName("cert_2001"))
                .doesNotThrowAnyException();
        assertThatCode(() -> driver.assertValidName("AbC-123_xyz"))
                .doesNotThrowAnyException();
    }

    @Test
    void provider_returnsExpectedTag() {
        SecretStoreDriver driver = newDriver();
        assertThat(driver.provider()).isEqualTo(expectedProvider());
    }

    protected abstract SecretStoreProvider expectedProvider();
}
