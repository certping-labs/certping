// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.ejbca;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Outcome of signing one CSR at EJBCA.
 *
 * <p>No private key appears here by design: in the SCEP flow the device generated the key and
 * never sent it, so the agent has nothing to store or leak.
 *
 * @param endEntityName the EJBCA end entity this certificate was issued under — worth logging,
 *                      since it is the key an operator searches by in the EJBCA admin UI
 */
public record EjbcaSignResult(
        String certificatePem,
        List<String> chainPem,
        String fullChainPem,
        String serialNumber,
        String endEntityName,
        X509Certificate leaf
) {}
