// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

/**
 * Records of one kind across organizations (or within one) that switching a feature off would affect.
 */
public record ImpactCount(BlockerKind kind, String label, long count, long organizations) {
}
