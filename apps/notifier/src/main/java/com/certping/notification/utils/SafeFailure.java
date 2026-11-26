// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.notification.utils;

import java.util.regex.Pattern;

/**
 * A failure as a log line may carry it: its type and its message with every email address masked.
 * A mail server's rejection text names the recipient, and a stack trace would print that text
 * again, so a line that uses this passes no throwable.
 */
public final class SafeFailure {

    private static final Pattern ADDRESS = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+");
    private static final String MASK = "<address>";

    private SafeFailure() {
    }

    public static String describe(Throwable failure) {
        String message = failure.getMessage() == null ? "" : ADDRESS.matcher(failure.getMessage()).replaceAll(MASK);
        return failure.getClass().getSimpleName() + ": " + message;
    }
}
