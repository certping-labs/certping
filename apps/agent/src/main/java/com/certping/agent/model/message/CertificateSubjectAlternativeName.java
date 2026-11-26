// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.model.message;

/** Structured subject alternative name parsed from the issued leaf certificate. */
public record CertificateSubjectAlternativeName(String type, String oid, String value) {
}
