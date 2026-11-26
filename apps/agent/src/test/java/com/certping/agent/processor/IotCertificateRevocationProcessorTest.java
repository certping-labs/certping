// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.listener.AgentMessageSender;
import com.certping.agent.model.message.IotCertificateRevocationMessage;
import com.certping.agent.model.message.IotCertificateRevocationResponse;
import com.certping.agent.ssl.ejbca.EjbcaRevocationService;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IotCertificateRevocationProcessorTest {
    @Mock private EjbcaRevocationService ejbca;
    @Mock private SmallstepRevocationService smallstep;
    @Mock private AgentMessageSender sender;
    @Mock private InboundContext context;
    private IotCertificateRevocationProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new IotCertificateRevocationProcessor(ejbca, smallstep, sender);
    }

    @Test
    void dispatchesSmallstepCommandsAndConfirmsOnlyAfterTheServiceConfirms() {
        IotCertificateRevocationMessage message = message("SMALLSTEP", "op-1:tx-7:1");
        when(smallstep.revoke("CN=Issuer", "abc", "KEY_COMPROMISE"))
                .thenReturn(new SmallstepRevocationService.Result(
                        false, "KEY_COMPROMISE", "2026-09-01T00:00:00Z"));

        processor.process(message, context);

        ArgumentCaptor<IotCertificateRevocationResponse> response =
                ArgumentCaptor.forClass(IotCertificateRevocationResponse.class);
        verify(sender).sendIotCertificateRevocationResponse(response.capture());
        assertThat(response.getValue().getOutcome()).isEqualTo("CONFIRMED");
        assertThat(response.getValue().getRequestId()).isEqualTo("op-1:tx-7:1");
        verify(context).complete();
    }

    @Test
    void rejectsARequestIdThatDoesNotBelongToTheOperation() {
        IotCertificateRevocationMessage message = message("SMALLSTEP", "other:tx-7:1");

        processor.process(message, context);

        ArgumentCaptor<IotCertificateRevocationResponse> response =
                ArgumentCaptor.forClass(IotCertificateRevocationResponse.class);
        verify(sender).sendIotCertificateRevocationResponse(response.capture());
        assertThat(response.getValue().getOutcome()).isEqualTo("FAILED");
        assertThat(response.getValue().getErrorCode())
                .isEqualTo("IOT_REVOCATION_COMMAND_INVALID");
        verify(context).complete();
    }

    private static IotCertificateRevocationMessage message(String provider, String requestId) {
        IotCertificateRevocationMessage message = new IotCertificateRevocationMessage();
        message.setRequestId(requestId);
        message.setCorrelationId("op-1");
        message.setOrganizationId("42");
        message.setOperationXref("op-1");
        message.setDispatchAttempt(1);
        message.setCertificateXref("crt-1");
        message.setCaProvider(provider);
        message.setIssuerDn("CN=Issuer");
        message.setSerialNumber("abc");
        message.setReason("KEY_COMPROMISE");
        return message;
    }
}
