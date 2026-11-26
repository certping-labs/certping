// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository.lifecycle;

/** How many records, held by how many organizations. */
public record RecordImpact(long records, long organizations) {
}
