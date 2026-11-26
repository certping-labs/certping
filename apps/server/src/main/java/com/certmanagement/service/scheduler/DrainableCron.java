// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

public interface DrainableCron {

    /**
     * @return {@code true} if a row was processed (drain loop continues),
     *         {@code false} if nothing was eligible (drain loop exits).
     *         One-shot jobs should always return {@code false}.
     */
    boolean tryProcessOneEligible();
}
