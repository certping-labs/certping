// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.revocation;

public enum IotIntuneRevocationPollStatus {
    IDLE,
    PENDING_POLL,
    POLL_DISPATCHED,
    PROCESSING,
    PENDING_UPLOAD,
    UPLOAD_DISPATCHED,
    FAILED
}
