// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import java.math.BigDecimal;
import java.util.Optional;

/** The cost a CA reported for an order, as the certificate keeps it: a decimal amount and a 3-letter currency. */
public record CaOrderCostValue(BigDecimal amount, String currency) {

    public static Optional<CaOrderCostValue> parse(String amount, String currency) {
        if (amount == null || amount.isBlank() || currency == null || currency.trim().length() != 3) {
            return Optional.empty();
        }
        try {
            BigDecimal value = new BigDecimal(amount.trim());
            return value.signum() < 0 || value.scale() > 2 || value.precision() - value.scale() > 8
                    ? Optional.empty()
                    : Optional.of(new CaOrderCostValue(value, currency.trim().toUpperCase()));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
