// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.utils;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SafeFailureTest {

    @Test
    void namesTheTypeAndMasksEveryAddress() {
        IllegalStateException rejection = new IllegalStateException(
                "550 5.1.1 <ada@example.com>: Recipient address rejected; cc grace.hopper+x@mail.example.org");

        assertThat(SafeFailure.describe(rejection)).isEqualTo(
                "IllegalStateException: 550 5.1.1 <<address>>: Recipient address rejected; cc <address>");
    }

    @Test
    void aFailureWithNoMessageIsItsType() {
        assertThat(SafeFailure.describe(new IllegalStateException())).isEqualTo("IllegalStateException: ");
    }
}
