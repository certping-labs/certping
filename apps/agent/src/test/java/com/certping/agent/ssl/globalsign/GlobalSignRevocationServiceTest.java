// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.globalsign;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class GlobalSignRevocationServiceTest {

    @Mock private GlobalSignAtlasClient atlasClient;

    private GlobalSignRevocationService service;
    private final ObjectMapper mapper = JsonMapper.builderWithJackson2Defaults().build();

    @BeforeEach
    void setUp() {
        service = new GlobalSignRevocationService(atlasClient);
    }

    @Test
    void revoke_blankSerial_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke("", "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("MISSING_ORDER_ID"));
        verifyNoInteractions(atlasClient);
    }

    @Test
    void revoke_nullSerial_throwsPermanent() {
        assertThatThrownBy(() -> service.revoke(null, "KEY_COMPROMISE"))
                .isInstanceOf(PermanentAgentException.class);
        verifyNoInteractions(atlasClient);
    }

    @Test
    void revoke_alreadyRevoked_isNoOp() throws Exception {
        JsonNode body = mapper.readTree("{\"status\":\"REVOKED\"}");
        when(atlasClient.getCertificate(eq("serial-A"))).thenReturn(body);

        service.revoke("serial-A", "SUPERSEDED");

        verify(atlasClient).getCertificate(eq("serial-A"));
        verify(atlasClient, never()).revokeCertificate(anyString(), anyString());
    }

    @Test
    void revoke_happyPath_callsRevokeCertificate() throws Exception {
        JsonNode body = mapper.readTree("{\"status\":\"ISSUED\"}");
        when(atlasClient.getCertificate(eq("serial-B"))).thenReturn(body);

        service.revoke("serial-B", "KEY_COMPROMISE");

        verify(atlasClient).revokeCertificate(eq("serial-B"), eq("KEY_COMPROMISE"));
    }

    @Test
    void revoke_atlasThrowsPermanent_propagates() throws Exception {
        when(atlasClient.getCertificate(anyString()))
                .thenThrow(new PermanentAgentException("GLOBALSIGN_API_ERROR", "boom"));

        assertThatThrownBy(() -> service.revoke("serial-C", "UNSPECIFIED"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void revoke_missingStatus_proceedsToRevoke() throws Exception {
        // Body has no status field — empty string is treated as not-revoked → revoke proceeds.
        JsonNode body = mapper.readTree("{}");
        when(atlasClient.getCertificate(eq("serial-D"))).thenReturn(body);

        service.revoke("serial-D", null);

        verify(atlasClient).revokeCertificate(eq("serial-D"), eq(null));
    }
}
