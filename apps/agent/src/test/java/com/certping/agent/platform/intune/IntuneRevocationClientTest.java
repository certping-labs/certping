// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.scep.intune.IntuneScepClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.restclient.RestTemplateBuilder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class IntuneRevocationClientTest {
    @Mock private DeviceSourceCredentialRegistry credentialRegistry;
    @Mock private IntuneScepClient intuneScepClient;

    @Test
    void rejectsInternalErrorNamesBeforeCallingIntune() {
        IntuneRevocationClient client = new IntuneRevocationClient(
                credentialRegistry, intuneScepClient, JsonMapper.builderWithJackson2Defaults().build(),
                new RestTemplateBuilder());

        assertThatThrownBy(() -> client.upload("profile", "tx", List.of(
                new IntuneRevocationClient.RevocationResult(
                        "ctx", false, "CERTIFICATE_NOT_FOUND", "not found"))))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("connector contract");
        verifyNoInteractions(credentialRegistry, intuneScepClient);
    }

    @Test
    void rejectsSuccessWithoutMicrosoftSuccessCode() {
        IntuneRevocationClient client = new IntuneRevocationClient(
                credentialRegistry, intuneScepClient, JsonMapper.builderWithJackson2Defaults().build(),
                new RestTemplateBuilder());

        assertThatThrownBy(() -> client.upload("profile", "tx", List.of(
                new IntuneRevocationClient.RevocationResult(
                        "ctx", true, "4000", null))))
                .isInstanceOf(PermanentAgentException.class);
    }
}
