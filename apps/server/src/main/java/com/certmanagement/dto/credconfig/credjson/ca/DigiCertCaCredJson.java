// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.ca;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/** A customer's DigiCert CertCentral API key, stored as {@code {"apiKey":"..."}}; the agent sends it as X-DC-DEVKEY. */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class DigiCertCaCredJson implements CredJsonPayload {
    private String apiKey;
}
