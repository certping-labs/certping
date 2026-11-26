// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.testing;

import com.certmanagement.service.FeatureFlagResolver;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/** {@link FeatureFlagResolver} stand-ins for unit tests that are not about flags. */
public final class FeatureFlagResolvers {

    private FeatureFlagResolvers() {
    }

    /** A resolver that answers "on" for every flag and organization, cached or not. */
    public static FeatureFlagResolver allEnabled() {
        FeatureFlagResolver resolver = mock(FeatureFlagResolver.class);
        lenient().when(resolver.resolve(anyString(), any())).thenReturn(true);
        lenient().when(resolver.resolveUncached(anyString(), any())).thenReturn(true);
        return resolver;
    }
}
