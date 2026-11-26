// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.messaging;

import tools.jackson.core.JacksonException;

/**
 * What a failed publish says about the message: certainly not sent, or perhaps sent. A command that may have been
 * sent must not be followed by a second attempt, which would race the first at the CA.
 */
public enum PublishOutcome {

    /** The message never reached the queue: it could not be built or serialized. */
    NOT_SENT,
    /** The queue may hold the message: a timeout, a lost connection or an unclassified error. */
    UNKNOWN;

    /** Classifies the failure thrown by a publish. */
    public static PublishOutcome of(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof JacksonException || cause instanceof IllegalArgumentException) {
                return NOT_SENT;
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return UNKNOWN;
    }
}
