// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.service;

class EmailSendDeadlineException extends RuntimeException {
    EmailSendDeadlineException(String message) {
        super(message);
    }
}
