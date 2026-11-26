// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.certificate;

import com.certmanagement.iot.messaging.IotDeviceSyncCommand;
import com.certmanagement.messaging.CertAgentPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;

/** Publishes prepared device-sync commands only after their database state commits. */
@Slf4j
@Component
@RequiredArgsConstructor
class IotDeviceSyncCommandPublisher {

    private final CertAgentPublisher certAgentPublisher;
    private final IotDeviceNudgeResultService resultService;

    void publishAfterCommit(List<IotDeviceSyncCommand> commands) {
        if (commands.isEmpty()) {
            return;
        }
        Runnable publish = () -> commands.forEach(this::publish);
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            publish.run();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                publish.run();
            }
        });
    }

    private void publish(IotDeviceSyncCommand command) {
        try {
            certAgentPublisher.publishDeviceSync(command);
        } catch (RuntimeException exception) {
            log.error("Could not publish Intune device sync: requestId={} device={} reason={}",
                    command.getRequestId(), command.getDeviceXref(), exception.getMessage());
            resultService.recordPublishFailure(command);
        }
    }
}
