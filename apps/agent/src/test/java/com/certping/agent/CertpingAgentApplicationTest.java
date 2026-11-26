// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
class CertpingAgentApplicationTest {

    @Test
    void main_delegatesToSpringApplicationRun() {
        ConfigurableApplicationContext ctx = mock(ConfigurableApplicationContext.class);
        try (MockedStatic<SpringApplication> spring = mockStatic(SpringApplication.class)) {
            spring.when(() -> SpringApplication.run(eq(CertpingAgentApplication.class), any(String[].class)))
                    .thenReturn(ctx);
            String[] args = new String[] {"--spring.main.banner-mode=off"};
            CertpingAgentApplication.main(args);
            spring.verify(() -> SpringApplication.run(CertpingAgentApplication.class, args));
        }
    }
}
