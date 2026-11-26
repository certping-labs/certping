// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.platform.DeviceSourceCredentialRegistry;
import com.certping.agent.scep.intune.IntuneScepClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IntuneRevocationClientContextTest {
    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(IntuneClientConfiguration.class);

    @Test
    void createsRevocationClientWithoutScepConfiguration() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(IntuneScepClient.class);
            assertThat(context).hasSingleBean(IntuneRevocationClient.class);
        });
    }

    @TestConfiguration(proxyBeanMethods = false)
    @Import({IntuneScepClient.class, IntuneRevocationClient.class})
    static class IntuneClientConfiguration {
        @Bean
        RestTemplateBuilder restTemplateBuilder() {
            return new RestTemplateBuilder();
        }

        @Bean
        ObjectMapper objectMapper() {
            return JsonMapper.builderWithJackson2Defaults().build();
        }

        @Bean
        DeviceSourceCredentialRegistry credentialRegistry() {
            return mock(DeviceSourceCredentialRegistry.class);
        }
    }
}
