// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/** A SCEP HTTP response body plus its content type. */
public record BinaryResponse(String contentType, byte[] body) {
}
