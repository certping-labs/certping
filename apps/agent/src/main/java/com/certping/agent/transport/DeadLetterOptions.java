// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.transport;

/** Why a message is dead-lettered: a short reason code and a longer description. */
public class DeadLetterOptions {

    private String deadLetterReason;
    private String deadLetterErrorDescription;

    public String getDeadLetterReason() {
        return deadLetterReason;
    }

    public DeadLetterOptions setDeadLetterReason(String deadLetterReason) {
        this.deadLetterReason = deadLetterReason;
        return this;
    }

    public String getDeadLetterErrorDescription() {
        return deadLetterErrorDescription;
    }

    public DeadLetterOptions setDeadLetterErrorDescription(String deadLetterErrorDescription) {
        this.deadLetterErrorDescription = deadLetterErrorDescription;
        return this;
    }
}
