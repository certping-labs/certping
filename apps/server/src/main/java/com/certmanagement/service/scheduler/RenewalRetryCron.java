// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Retries failed renewals when their retry is due, every few minutes, instead of at the next daily
 * trigger-renewals run. First attempts and holds stay on the daily run.
 */
@Service
@RequiredArgsConstructor
@CronJobFor("retry-renewals")
public class RenewalRetryCron implements DrainableCron {

    private final RenewalTriggerService renewalTriggerService;

    @Override
    public boolean tryProcessOneEligible() {
        return renewalTriggerService.tryProcessOneDueRetry();
    }
}
