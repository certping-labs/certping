// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

import java.time.OffsetDateTime;

/** A user's per-request access state ({@link UserRepository#findAccessStateById}). */
public interface UserAccessStateProjection extends ActivationStateProjection {

    Boolean getMustChangePassword();

    /** Access tokens issued before this are refused; null refuses none. */
    OffsetDateTime getTokensValidAfter();
}
