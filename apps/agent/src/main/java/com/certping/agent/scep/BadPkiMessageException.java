// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep;

/** The pkiMessage could not be parsed as CMS — no signed {@code CertRep} can be built. HTTP 400. */
public class BadPkiMessageException extends RuntimeException {
    public BadPkiMessageException(Throwable cause) {
        super("pkiMessage is not valid CMS", cause);
    }
}
