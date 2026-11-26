// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.listener;

import com.certping.agent.transport.MessageSender;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import java.time.Clock;

import static org.mockito.Mockito.mock;

/** {@link AttemptRecords} over {@code store}, with the default attempt-age bounds. */
public final class TestAttemptRecords {

    private TestAttemptRecords() {
    }

    public static AttemptRecords over(SecretStore store) {
        return over(store, Clock.systemUTC());
    }

    public static AttemptRecords over(SecretStore store, Clock clock) {
        return new AttemptRecords(store, JsonMapper.builderWithJackson2Defaults().build(), new ScheduledRetryService(
                mock(MessageSender.class), new AgentProperties(), new SimpleMeterRegistry(), clock), clock);
    }
}
