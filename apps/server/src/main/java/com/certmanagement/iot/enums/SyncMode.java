// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.enums;

/**
 * What a sync run is for.
 *
 * <p>There is no incremental mode. Only a full sweep returns the complete device list, and
 * without that a device deleted at the source is indistinguishable from one that did not
 * change — so orphan detection would be impossible.
 */
public enum SyncMode {

    /** Every device. The only mode that ingests, and the only one orphan detection runs after. */
    FULL
}
