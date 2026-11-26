// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery;

import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;

import java.util.List;

/**
 * Common contract for scanning a deployment target and returning all certificates found there.
 */
public interface DiscoveryAdapter {

    /**
     * Scans the deployment target identified in {@code message} and returns metadata for every
     * certificate found. The returned list may be empty if the target has no certificates.
     */
    List<DiscoveredCertEntry> discover(CertDiscoveryMessage message);

    /**
     * Same scan as {@link #discover}, but also reports the scopes (accounts, regions, vaults,
     * namespaces) that could not be read, so the server does not treat their certificates as
     * gone. Adapters that scan more than one scope override this; the default reports none.
     */
    default DiscoveryResult discoverWithFailedScopes(CertDiscoveryMessage message) {
        return DiscoveryResult.complete(discover(message));
    }
}
