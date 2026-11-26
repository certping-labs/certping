// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.handler.acme;

import java.net.URL;
import java.security.KeyPair;

/**
 * Result returned by AcmeAccountService.getOrCreate().
 * The acmeAccountHandle is the KV URI where the account key PEM is stored.
 * It must be echoed back in CERT_ISSUANCE_RESPONSE so certping stores it
 * for all future LE issuances for this organization.
 */
public record AcmeAccountResult(
        KeyPair keyPair,
        URL accountLocation,
        String acmeAccountHandle
) {}
