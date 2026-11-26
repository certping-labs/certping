// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.config.AgentProperties;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.AgentDeepHealthCheckMessage;
import com.certping.agent.model.message.AgentDeepHealthCheckResponse;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AgentDeepHealthCheckProcessorTest {

    @Mock private SecretStore secretStore;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;

    private AgentDeepHealthCheckProcessor processor;

    @BeforeEach
    void setUp() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId("10");
        properties.getTransport().setServerUrl("https://certping.example.com");
        properties.getTransport().setToken("cpa_test");
        processor = new AgentDeepHealthCheckProcessor(properties, secretStore, sender);
    }

    @Test
    void process_whenAllKvPathsReadable_sendsSuccess() {
        when(secretStore.read("https://kv.vault.azure.net/secrets/one")).thenReturn("ok");

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-1");
        message.setRequestId("req-1");
        message.setCorrelationId("corr-1");
        message.setOrganizationId("10");
        message.setChunkIndex(0);
        message.setTotalChunks(1);
        message.setSecretHandles(List.of("https://kv.vault.azure.net/secrets/one"));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("SUCCESS");
        assertThat(captor.getValue().getMetrics()).isNotEmpty();
        verify(context).complete();
    }

    @Test
    void process_whenOrgIdMismatch_completesEarlyWithoutSending() {
        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setOrganizationId("99"); // configured is "10"

        processor.process(message, context);

        verify(context).complete();
        verifyNoInteractions(sender);
        verifyNoInteractions(secretStore);
    }

    @Test
    void process_whenIdsAreNull_generatesUuidFallbacks() {
        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        // organizationId, requestId, correlationId, deepCheckId, chunkIndex, totalChunks all null

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        AgentDeepHealthCheckResponse r = captor.getValue();
        assertThat(r.getRequestId()).startsWith("req-");
        assertThat(r.getCorrelationId()).startsWith("corr-");
        assertThat(r.getDeepCheckId()).startsWith("dhc-");
        assertThat(r.getChunkIndex()).isEqualTo(0);
        assertThat(r.getTotalChunks()).isEqualTo(1);
        assertThat(r.getStatus()).isEqualTo("SUCCESS");
    }

    @Test
    void process_whenOrgIdConfiguredBlank_organizationMetricFails() {
        AgentProperties properties = new AgentProperties();
        properties.setOrganizationId(""); // blank -> FAIL branch
        properties.getTransport().setServerUrl("https://certping.example.com");
        properties.getTransport().setToken(" "); // blank token -> gateway metric FAILs
        AgentDeepHealthCheckProcessor blankProcessor =
                new AgentDeepHealthCheckProcessor(properties, secretStore, sender);

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        // organizationId null on the message → skip the mismatch guard
        message.setDeepCheckId("dhc-blank");

        blankProcessor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        AgentDeepHealthCheckResponse r = captor.getValue();
        assertThat(r.getMetrics())
                .anyMatch(m -> "agent.organizationId.present".equals(m.getMetricKey()) && "FAIL".equals(m.getStatus()));
        assertThat(r.getMetrics())
                .anyMatch(m -> "agent.gateway.connection.present".equals(m.getMetricKey()) && "FAIL".equals(m.getStatus()));
    }

    @Test
    void process_whenKvPathsContainsBlankAndNull_skipsWithoutError() {
        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-3");
        message.setOrganizationId("10");
        message.setSecretHandles(java.util.Arrays.asList(null, "", "   "));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        // Only the two config metrics — no KV metrics — status still SUCCESS
        assertThat(captor.getValue().getStatus()).isEqualTo("SUCCESS");
        assertThat(captor.getValue().getMetrics()).hasSize(2);
        verify(secretStore, never()).read(org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void process_whenKvExceptionMessageIsVeryLong_truncatesToThreeHundredChars() {
        String longMsg = "x".repeat(500); // exercises sanitize truncation branch
        doThrow(new RuntimeException(longMsg))
                .when(secretStore).read("https://kv.vault.azure.net/secrets/big");

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-4");
        message.setOrganizationId("10");
        message.setSecretHandles(List.of("https://kv.vault.azure.net/secrets/big"));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        String details = captor.getValue().getMetrics().stream()
                .filter(m -> "FAIL".equals(m.getStatus()))
                .findFirst()
                .orElseThrow()
                .getDetails();
        assertThat(details).hasSize(300);
    }

    @Test
    void process_whenKvExceptionMessageIsNull_sanitizeReturnsNull() {
        doThrow(new RuntimeException((String) null))
                .when(secretStore).read("https://kv.vault.azure.net/secrets/nullmsg");

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-5");
        message.setOrganizationId("10");
        message.setSecretHandles(List.of("https://kv.vault.azure.net/secrets/nullmsg"));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        String details = captor.getValue().getMetrics().stream()
                .filter(m -> "FAIL".equals(m.getStatus()))
                .findFirst()
                .orElseThrow()
                .getDetails();
        assertThat(details).isNull();
    }

    @Test
    void process_whenKvExceptionMessageHasNewlines_stripsThem() {
        doThrow(new RuntimeException("line1\nline2\rline3"))
                .when(secretStore).read("https://kv.vault.azure.net/secrets/nl");

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-6");
        message.setOrganizationId("10");
        message.setSecretHandles(List.of("https://kv.vault.azure.net/secrets/nl"));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        String details = captor.getValue().getMetrics().stream()
                .filter(m -> "FAIL".equals(m.getStatus()))
                .findFirst()
                .orElseThrow()
                .getDetails();
        assertThat(details).doesNotContain("\n").doesNotContain("\r");
    }

    @Test
    void process_whenKvReadFails_marksPartial() {
        doThrow(new RuntimeException("secret not found"))
                .when(secretStore).read("https://kv.vault.azure.net/secrets/missing");

        AgentDeepHealthCheckMessage message = new AgentDeepHealthCheckMessage();
        message.setDeepCheckId("dhc-2");
        message.setRequestId("req-2");
        message.setCorrelationId("corr-2");
        message.setOrganizationId("10");
        message.setChunkIndex(0);
        message.setTotalChunks(1);
        message.setSecretHandles(List.of("https://kv.vault.azure.net/secrets/missing"));

        processor.process(message, context);

        ArgumentCaptor<AgentDeepHealthCheckResponse> captor = ArgumentCaptor.forClass(AgentDeepHealthCheckResponse.class);
        verify(sender).sendDeepHealthCheckResponse(captor.capture());
        assertThat(captor.getValue().getStatus()).isEqualTo("PARTIAL");
        assertThat(captor.getValue().getMetrics().stream().anyMatch(m -> "FAIL".equals(m.getStatus()))).isTrue();
        verify(context).complete();
    }
}
