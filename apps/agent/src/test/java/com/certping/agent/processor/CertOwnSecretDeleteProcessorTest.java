// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.processor;

import com.certping.agent.transport.InboundContext;
import com.certping.agent.listener.AttemptRecords;
import com.certping.agent.model.message.CertOwnSecretDeleteMessage;
import com.certping.agent.secrets.SecretStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertOwnSecretDeleteProcessorTest {

    private static final String HANDLE_1 = "https://kv.vault.azure.net/secrets/cert-xref-1";
    private static final String HANDLE_2 = "https://kv.vault.azure.net/secrets/cert-xref-2";

    @Mock private SecretStore secretStore;
    @Mock private AttemptRecords attemptRecords;
    @Mock private InboundContext context;

    private CertOwnSecretDeleteProcessor processor;

    @BeforeEach
    void setUp() {
        processor = new CertOwnSecretDeleteProcessor(secretStore, attemptRecords);
    }

    @Test
    void process_ownHandle_purgesAndCompletes() {
        when(secretStore.isOwnedByThisAgent(HANDLE_1)).thenReturn(true);
        CertOwnSecretDeleteMessage msg = new CertOwnSecretDeleteMessage();
        msg.setCertificateXref("xref-1");
        msg.setCertSecretHandle(HANDLE_1);
        msg.setReason("CERT_EXPIRED");

        processor.process(msg, context);

        verify(secretStore).isOwnedByThisAgent(HANDLE_1);
        verify(secretStore).delete(HANDLE_1);
        verify(attemptRecords).delete("xref-1");
        verify(context).complete();
    }

    @Test
    void process_foreignHandle_skipsDeleteAndCompletes() {
        when(secretStore.isOwnedByThisAgent(HANDLE_2)).thenReturn(false);
        CertOwnSecretDeleteMessage msg = new CertOwnSecretDeleteMessage();
        msg.setCertificateXref("xref-2");
        msg.setCertSecretHandle(HANDLE_2);
        msg.setReason(" ");

        processor.process(msg, context);

        verify(secretStore).isOwnedByThisAgent(HANDLE_2);
        verify(secretStore, never()).delete(HANDLE_2);
        verify(context).complete();
    }
}
