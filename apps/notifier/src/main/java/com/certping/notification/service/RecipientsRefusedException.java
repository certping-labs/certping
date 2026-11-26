// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

/**
 * Every recipient that could receive a deliver-once email has it, and the rest refused their address
 * for good: nothing is left to retry.
 */
class RecipientsRefusedException extends RuntimeException {

    RecipientsRefusedException(int refused) {
        super(refused + " recipient(s) refused the email for good");
    }
}
