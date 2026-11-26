// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.exception.BadRequestException;

/** The requested bulk action does not clear that kind (or the kind is link-only). Maps to 400. */
public class UnsupportedClearException extends BadRequestException {

    public UnsupportedClearException(String featureKey, BlockerKind kind, ClearAction action) {
        super("'" + action + "' cannot clear " + kind + " for feature '" + featureKey
                + "'. Open the linked page to change these records.");
    }
}
