// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import java.util.List;

/**
 * Records of one kind that keep a feature in use for an organization, as the disable dialog and the
 * 409 {@code FEATURE_IN_USE} body show them.
 *
 * @param href    the page where the records are managed
 * @param actions the bulk actions that clear them; empty for a link-only kind
 */
public record Blocker(BlockerKind kind, String label, long count, String href, List<ClearAction> actions) {

    public Blocker {
        actions = List.copyOf(actions);
    }
}
