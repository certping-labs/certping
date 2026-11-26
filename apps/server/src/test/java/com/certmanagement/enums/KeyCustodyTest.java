// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.enums;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class KeyCustodyTest {

    @Test
    void readsTheCustodyAnAgentNames() {
        assertThat(KeyCustody.fromResponse("CUSTOMER_HELD")).contains(KeyCustody.CUSTOMER_HELD);
        assertThat(KeyCustody.fromResponse(" platform_held ".toUpperCase())).contains(KeyCustody.PLATFORM_HELD);
    }

    @Test
    void anOlderAgentNamesNone() {
        assertThat(KeyCustody.fromResponse(null)).isEmpty();
        assertThat(KeyCustody.fromResponse("")).isEmpty();
        assertThat(KeyCustody.fromResponse("SHARED")).isEmpty();
    }

    @Test
    void accountSourceFollowsTheCa() {
        assertThat(CaAccountSource.forIssuance(CaProvider.LETS_ENCRYPT, false)).isNull();
        assertThat(CaAccountSource.forIssuance(CaProvider.GLOBALSIGN, false)).isEqualTo(CaAccountSource.PLATFORM);
        assertThat(CaAccountSource.forIssuance(CaProvider.DIGICERT, true)).isEqualTo(CaAccountSource.CUSTOMER);
        assertThat(CaAccountSource.forIssuance(null, true)).isNull();
    }
}
