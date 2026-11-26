// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.dns;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/** Non-secret Namecheap account metadata, kept in the credential's configuration rather than its secret. */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class NamecheapDnsConfigJson implements CredJsonPayload {
    private String apiUser;
    private String username;
}
