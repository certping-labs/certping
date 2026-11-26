// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

import com.certping.agent.model.enums.CaProvider;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JSON contract tests for manual issuance DTOs (server ↔ agent).
 */
class CertManualMessageJsonTest {

    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = JsonMapper.builderWithJackson2Defaults().build();
    }

    @Test
    void certManualTxtRequest_roundTrip() throws Exception {
        String json = """
                {
                  "requestId": "r1",
                  "correlationId": "c1",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "wildcard": true,
                  "san": false,
                  "caProvider": "LETS_ENCRYPT",
                  "acmeAccountHandle": "https://kv/secrets/acct",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "requestedAt": "2025-01-01T00:00:00Z"
                }
                """;

        CertManualTxtRequestMessage msg = mapper.readValue(json, CertManualTxtRequestMessage.class);
        assertThat(msg.getOrganizationId()).isEqualTo("organization-1");
        assertThat(msg.getCaProvider()).isEqualTo(CaProvider.LETS_ENCRYPT);
        assertThat(msg.isWildcard()).isTrue();

        String out = mapper.writeValueAsString(msg);
        CertManualTxtRequestMessage again = mapper.readValue(out, CertManualTxtRequestMessage.class);
        assertThat(again.getCertificateXref()).isEqualTo("xref-1");
    }

    @Test
    void certManualValidate_withTxtRecords_roundTrip() throws Exception {
        String json = """
                {
                  "requestId": "r2",
                  "correlationId": "c2",
                  "organizationId": "organization-1",
                  "certificateXref": "xref-1",
                  "domain": "example.com",
                  "wildcard": false,
                  "san": true,
                  "caProvider": "LETS_ENCRYPT",
                  "acmeAccountHandle": "https://kv/secrets/acct",
                  "acmeOrderUrl": "https://acme.test/order/1",
                  "certSecretHandle": "https://kv/secrets/cert",
                  "txtRecords": [
                    { "recordName": "_acme-challenge.example.com", "recordValue": "token" }
                  ]
                }
                """;

        CertManualValidateMessage msg = mapper.readValue(json, CertManualValidateMessage.class);
        assertThat(msg.getTxtRecords()).hasSize(1);
        assertThat(msg.getTxtRecords().get(0).getRecordName()).contains("_acme-challenge");
        assertThat(msg.getAcmeOrderUrl()).contains("order");

        String out = mapper.writeValueAsString(msg);
        assertThat(out).contains("txtRecords");
    }

    @Test
    void certManualTxtResponse_serializesForOutbound() throws Exception {
        CertManualTxtResponse response = CertManualTxtResponse.builder()
                .requestId("r3")
                .organizationId("organization-1")
                .certificateXref("xref-1")
                .txtRecords(List.of(CertManualTxtResponse.TxtRecord.builder()
                        .domain("example.com")
                        .recordName("_acme-challenge.example.com")
                        .recordValue("digest")
                        .build()))
                .acmeOrderUrl("https://acme/order")
                .acmeAccountHandle("https://kv/acct")
                .respondedAt("2025-01-02T00:00:00Z")
                .build();

        String json = mapper.writeValueAsString(response);
        assertThat(json).contains("organization-1");
        assertThat(json).contains("acmeOrderUrl");
        assertThat(json).contains("digest");

        CertManualTxtResponse parsed = mapper.readValue(json, CertManualTxtResponse.class);
        assertThat(parsed.getTxtRecords()).hasSize(1);
        assertThat(parsed.getTxtRecords().get(0).getRecordValue()).isEqualTo("digest");
    }

    @Test
    void unknownJsonPropertiesIgnored() throws Exception {
        String json = """
                {
                  "organizationId": "t",
                  "certificateXref": "x",
                  "domain": "d",
                  "certSecretHandle": "kv",
                  "caProvider": "LETS_ENCRYPT",
                  "futureField": 123
                }
                """;
        CertManualTxtRequestMessage msg = mapper.readValue(json, CertManualTxtRequestMessage.class);
        assertThat(msg.getDomain()).isEqualTo("d");
    }
}
