// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.credconfig.credjson.deployment;

import com.certmanagement.dto.credconfig.credjson.CredJsonPayload;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

/**
 * F5 BIG-IP iControl REST deployment.
 *
 * <p><b>Required (both):</b> {@code username}, {@code password}. Agent's iControl login fails without both.
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class F5BigIpDeploymentCredJson implements CredJsonPayload {
    private String username;
    private String password;
}
