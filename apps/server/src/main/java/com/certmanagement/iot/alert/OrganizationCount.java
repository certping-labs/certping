// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.iot.alert;

/** One aggregate row per organization, shared by the fleet health-check queries. */
public interface OrganizationCount {
    Long getOrganizationId();

    long getTotal();
}
