// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.util;

import com.certping.agent.exception.PermanentAgentException;
import org.shredzone.acme4j.util.KeyPairUtils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;

/**
 * Utilities for PEM serialization of RSA key pairs.
 * Wraps acme4j's KeyPairUtils so the rest of the codebase doesn't depend on it directly.
 */
public final class PemUtils {

    private PemUtils() {}

    public static String keyPairToPem(KeyPair keyPair) {
        try {
            StringWriter sw = new StringWriter();
            KeyPairUtils.writeKeyPair(keyPair, sw);
            return sw.toString();
        } catch (IOException e) {
            throw new PermanentAgentException("KEY_PAIR_SERIALIZE_FAILED",
                    "Failed to serialize key pair to PEM: " + e.getMessage(), e);
        }
    }

    public static KeyPair pemToKeyPair(String pem) {
        try {
            return KeyPairUtils.readKeyPair(new StringReader(pem));
        } catch (IOException e) {
            throw new PermanentAgentException("KEY_PAIR_PARSE_FAILED",
                    "Failed to parse PEM key pair: " + e.getMessage(), e);
        }
    }
}
