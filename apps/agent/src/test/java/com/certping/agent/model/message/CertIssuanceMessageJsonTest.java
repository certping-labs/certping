// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CertIssuanceMessageJsonTest {

    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

    @Test
    void carriesTheCustomersCsrAndCustody() throws Exception {
        CertIssuanceMessage msg = mapper.readValue("""
                {"certificateXref":"cert-1","domain":"example.com","caProvider":"DIGICERT",
                 "keyCustody":"CUSTOMER_HELD","csrPem":"-----BEGIN CERTIFICATE REQUEST-----\\nABC\\n-----END CERTIFICATE REQUEST-----"}
                """, CertIssuanceMessage.class);

        assertThat(msg.getKeyCustody()).isEqualTo("CUSTOMER_HELD");
        assertThat(msg.getCsrPem()).startsWith("-----BEGIN CERTIFICATE REQUEST-----");
    }

    @Test
    void anOlderMessageHasNeither() throws Exception {
        CertIssuanceMessage msg = mapper.readValue("""
                {"certificateXref":"cert-1","domain":"example.com","caProvider":"LETS_ENCRYPT"}
                """, CertIssuanceMessage.class);

        assertThat(msg.getKeyCustody()).isNull();
        assertThat(msg.getCsrPem()).isNull();
    }
}
