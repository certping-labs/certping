// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.model;

public enum NotificationStatus {
    PENDING,
    SENT,
    DELIVERED,
    FAILED,
    READ,
    /** Not sent: the organization turned off the notification's category (failure_reason names it). */
    SUPPRESSED
}
