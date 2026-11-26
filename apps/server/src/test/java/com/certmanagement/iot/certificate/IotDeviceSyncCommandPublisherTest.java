// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.messaging.CertAgentPublisher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class IotDeviceSyncCommandPublisherTest {

    @Mock private CertAgentPublisher agentPublisher;
    @Mock private IotDeviceNudgeResultService resultService;

    @AfterEach
    void clearSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    @Test
    void waitsForDatabaseCommitBeforePublishing() {
        IotDeviceSyncCommand command = command();
        TransactionSynchronizationManager.initSynchronization();

        new IotDeviceSyncCommandPublisher(agentPublisher, resultService)
                .publishAfterCommit(List.of(command));

        verify(agentPublisher, never()).publishDeviceSync(command);
        List<TransactionSynchronization> synchronizations =
                TransactionSynchronizationManager.getSynchronizations();
        synchronizations.forEach(TransactionSynchronization::afterCommit);
        verify(agentPublisher).publishDeviceSync(command);
    }

    @Test
    void recordsAPublishFailureWithoutReusingTheRolledBackTransaction() {
        IotDeviceSyncCommand command = command();
        doThrow(new IllegalStateException("broker unavailable"))
                .when(agentPublisher).publishDeviceSync(command);

        new IotDeviceSyncCommandPublisher(agentPublisher, resultService)
                .publishAfterCommit(List.of(command));

        verify(resultService).recordPublishFailure(command);
    }

    private static IotDeviceSyncCommand command() {
        return IotDeviceSyncCommand.builder().requestId("req-1").deviceXref("dev-1")
                .certificateXrefs(List.of("crt-1")).build();
    }
}
