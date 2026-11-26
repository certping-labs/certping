// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cbom;

/** Published after any write to a certificate, its crypto metadata or a discovered certificate, including bulk soft-deletes. */
public record CertificateInventoryChangedEvent() {
}
