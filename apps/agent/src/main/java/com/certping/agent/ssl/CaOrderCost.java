// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

/**
 * What the CA reported it charged for one order, exactly as it sent it. The agent does no
 * arithmetic or validation on it; the server parses and checks it before recording it.
 *
 * @param amount   the CA's figure as sent (e.g. {@code "210.00"}); null when absent
 * @param currency the currency the CA named, or null when it names none
 */
public record CaOrderCost(String amount, String currency) {

    /** The cost of an order, or null when the CA reported neither an amount nor a currency. */
    public static CaOrderCost of(String amount, String currency) {
        String reportedAmount = blankToNull(amount);
        String reportedCurrency = blankToNull(currency);
        if (reportedAmount == null && reportedCurrency == null) {
            return null;
        }
        return new CaOrderCost(reportedAmount, reportedCurrency);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
