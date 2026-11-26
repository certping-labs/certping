// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.exception;

import com.certmanagement.service.lifecycle.Blocker;

import java.util.List;

/**
 * An organization admin tried to switch off a feature that still has records running.
 * Maps to 409 {@code FEATURE_IN_USE} with the blockers, so the dialog can offer to clear them.
 */
public class FeatureInUseException extends RuntimeException {

    public static final String CODE = "FEATURE_IN_USE";

    private final String featureKey;
    private final List<Blocker> blockers;

    public FeatureInUseException(String featureKey, List<Blocker> blockers) {
        super("Feature '" + featureKey + "' is still in use. Pause or delete what is listed, then switch it off.");
        this.featureKey = featureKey;
        this.blockers = List.copyOf(blockers);
    }

    public String getFeatureKey() {
        return featureKey;
    }

    public List<Blocker> getBlockers() {
        return blockers;
    }
}
