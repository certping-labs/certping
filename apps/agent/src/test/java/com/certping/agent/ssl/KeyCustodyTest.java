// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KeyCustodyTest {

    @Test
    void aMessageThatNamesNoCustodyIsPlatformHeld() {
        assertThat(KeyCustody.fromMessage(null)).isEqualTo(KeyCustody.PLATFORM_HELD);
        assertThat(KeyCustody.fromMessage("")).isEqualTo(KeyCustody.PLATFORM_HELD);
        assertThat(KeyCustody.fromMessage("SHARED")).isEqualTo(KeyCustody.PLATFORM_HELD);
        assertThat(KeyCustody.fromMessage(" customer_held ")).isEqualTo(KeyCustody.CUSTOMER_HELD);
    }

    @Test
    void aBundleWithoutAKeyIsCustomerHeld() {
        assertThat(KeyCustody.ofStoredKey(null)).isEqualTo(KeyCustody.CUSTOMER_HELD);
        assertThat(KeyCustody.ofStoredKey("-----BEGIN PRIVATE KEY-----")).isEqualTo(KeyCustody.PLATFORM_HELD);
    }
}
