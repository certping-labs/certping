// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/** One DNS-01 TXT record the user must add to their DNS provider. */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TxtRecordDto {
    /** e.g. {@code _acme-challenge.example.com} */
    private String recordName;
    /** ACME digest value to set as the TXT record content */
    private String recordValue;
    /** The domain this ACME challenge is for */
    private String domain;
}
