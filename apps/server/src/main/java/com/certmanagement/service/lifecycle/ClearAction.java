// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

/** A one-click bulk action that clears a {@link BlockerKind}. Paused counts as cleared. */
public enum ClearAction {
    PAUSE_ALL,
    DELETE_ALL,
    CANCEL_ALL,
    CLEAR_TARGETS,
    DISABLE_AUTO_RENEW
}
