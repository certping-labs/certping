// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.iot.revocation.IotIntuneRevocationWorkflow;
import com.certmanagement.messaging.CertAgentPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@CronJobFor("process-intune-certificate-revocations")
@RequiredArgsConstructor
public class IotIntuneRevocationCron implements DrainableCron {
    private final IotIntuneRevocationWorkflow workflow;
    private final CertAgentPublisher publisher;

    @Override
    public boolean tryProcessOneEligible() {
        var claimed = workflow.claimNext();
        if (claimed.isEmpty()) return false;
        IotIntuneRevocationWorkflow.Work work = claimed.get();
        if (work.type() == IotIntuneRevocationWorkflow.WorkType.SKIP) return true;
        try {
            if (work.type() == IotIntuneRevocationWorkflow.WorkType.POLL) {
                publisher.publishIotIntuneRevocationPoll(work.pollCommand());
            } else {
                publisher.publishIotIntuneRevocationUpload(work.uploadCommand());
            }
            workflow.markDispatched(work.stateId(), work.attempt(), work.type());
        } catch (RuntimeException exception) {
            workflow.markPublishFailed(work.stateId(), work.attempt(),
                    "queue publish failed");
            log.warn("Intune revocation workflow publish failed state={} attempt={}: {}",
                    work.stateId(), work.attempt(), exception.getMessage());
        }
        return true;
    }
}
