// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

/**
 * How many records of one kind a platform pause or resume changed; becomes one {@code items} entry
 * ({@code label}, {@code count}) of the customer email.
 */
public record AffectedItems(BlockerKind kind, String label, int count) {
}
