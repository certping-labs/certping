// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.util;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.Test;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PemUtilsTest {

    @Test
    void keyPairToPem_and_pemToKeyPair_roundTrip() {
        KeyPair original = KeyPairUtils.createKeyPair(2048);
        String pem = PemUtils.keyPairToPem(original);
        KeyPair parsed = PemUtils.pemToKeyPair(pem);
        assertThat(parsed.getPrivate().getEncoded()).isEqualTo(original.getPrivate().getEncoded());
        assertThat(parsed.getPublic().getEncoded()).isEqualTo(original.getPublic().getEncoded());
    }

    @Test
    void pemToKeyPair_invalidPem_throwsPermanentAgentException() {
        assertThatThrownBy(() -> PemUtils.pemToKeyPair("not valid pem"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "KEY_PAIR_PARSE_FAILED");
    }
}
