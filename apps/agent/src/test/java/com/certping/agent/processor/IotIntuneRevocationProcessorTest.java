// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundMessage;
import com.certping.agent.transport.InboundContext;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.IotIntuneRevocationPollMessage;
import com.certping.agent.model.message.IotIntuneRevocationPollResponse;
import com.certping.agent.platform.intune.IntuneRevocationClient;
import com.certping.agent.platform.intune.IntuneRevocationReplayCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotIntuneRevocationProcessorTest {
    @Mock private IntuneRevocationClient client;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    @Mock private InboundMessage receivedMessage;
    private IotIntuneRevocationProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new IotIntuneRevocationProcessor(
                client, new IntuneRevocationReplayCache(), sender);
        when(context.getMessage()).thenReturn(receivedMessage);
        when(receivedMessage.getApplicationProperties()).thenReturn(Map.of());
    }

    @Test
    void asbSendRetryReplaysDownloadedBatchWithoutCallingIntuneAgain() {
        IotIntuneRevocationPollMessage message = pollMessage();
        List<IntuneRevocationClient.RevocationRequest> requests = List.of(
                new IntuneRevocationClient.RevocationRequest(
                        "ctx-1", "abc", "CN=Issuer", "ManagementCA"));
        when(client.download("intune-primary", "tx-1", 100)).thenReturn(requests);
        doThrow(new TransientAgentException("SEND_FAILED", "gateway unavailable"))
                .doNothing().when(sender).sendIotIntuneRevocationPollResponse(
                        org.mockito.ArgumentMatchers.any());

        assertThatThrownBy(() -> processor.poll(message, context))
                .isInstanceOf(TransientAgentException.class);
        processor.poll(message, context);

        verify(client, times(1)).download("intune-primary", "tx-1", 100);
        verify(context, times(1)).complete();
    }

    @Test
    void retryMetadataIsReportedToCms() {
        when(receivedMessage.getApplicationProperties()).thenReturn(Map.of("RetryCount", 1));
        when(client.download("intune-primary", "tx-1", 100)).thenReturn(List.of());
        ArgumentCaptor<IotIntuneRevocationPollResponse> response =
                ArgumentCaptor.forClass(IotIntuneRevocationPollResponse.class);

        processor.poll(pollMessage(), context);

        verify(sender).sendIotIntuneRevocationPollResponse(response.capture());
        assertThat(response.getValue().getRedelivered()).isTrue();
        assertThat(response.getValue().getDispatchAttempt()).isEqualTo(1);
    }

    private static IotIntuneRevocationPollMessage pollMessage() {
        IotIntuneRevocationPollMessage message = new IotIntuneRevocationPollMessage();
        message.setRequestId("tx-1:poll:1");
        message.setCorrelationId("tx-1");
        message.setOrganizationId("42");
        message.setSourceXref("src-1");
        message.setConnectionProfileRef("intune-primary");
        message.setTransactionId("tx-1");
        message.setDispatchAttempt(1);
        message.setMaxRequests(100);
        return message;
    }
}
