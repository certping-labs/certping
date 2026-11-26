// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import com.certmanagement.constants.FeatureFlags;
import lombok.Getter;

import java.util.Map;

/**
 * Thrown when a request targets a feature that has been disabled via a feature flag.
 * Mapped to HTTP 423 Locked by {@link GlobalExceptionHandler}.
 */
@Getter
public class FeatureDisabledException extends RuntimeException {

    private final String featureKey;
    private final String code;

    /**
     * The message for features only CertPing decides: generic, never saying who switched them off or
     * for whom.
     */
    private static final Map<String, String> UNAVAILABLE = Map.of(
            FeatureFlags.CERTIFICATE_RENEWAL, "Automatic renewal isn't available. Ask your CertPing administrator.",
            FeatureFlags.DNS_CREDENTIALS, FeatureFlags.DNS_CREDENTIALS_UNAVAILABLE,
            FeatureFlags.INTEGRATIONS, "Integrations aren't available. Ask your CertPing administrator.",
            FeatureFlags.FEATURE_FLAGS_PAGE, FeatureFlags.FEATURE_FLAGS_UNAVAILABLE,
            FeatureFlags.NOTIFICATION_PREFERENCES, FeatureFlags.NOTIFICATION_SETTINGS_UNAVAILABLE);

    public FeatureDisabledException(String featureKey) {
        super(UNAVAILABLE.getOrDefault(featureKey, "Feature '" + featureKey + "' is currently disabled."));
        this.featureKey = featureKey;
        this.code = "FEATURE_DISABLED";
    }

    public FeatureDisabledException(String featureKey, String code, String message) {
        super(message);
        this.featureKey = featureKey;
        this.code = code;
    }
}
