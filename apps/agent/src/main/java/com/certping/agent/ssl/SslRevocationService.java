// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.ssl.acme.LetsEncryptRevocationService;
import com.certping.agent.ssl.digicert.DigiCertRevocationService;
import com.certping.agent.ssl.globalsign.GlobalSignRevocationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Routes revocation to the CA-specific implementation.
 *
 * <p>Supported: LETS_ENCRYPT, DIGICERT, GLOBALSIGN.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SslRevocationService {

    private final LetsEncryptRevocationService leRevocationService;
    private final DigiCertRevocationService    dcRevocationService;
    private final GlobalSignRevocationService  globalSignRevocationService;

    /**
     * @param bundle          PEM bundle from the secret store (used for LE; presence-checked upstream for DC)
     * @param orderId         DigiCert order ID — ignored for LE
     * @param caCredentialRaw raw CA credential — DigiCert API key for DIGICERT
     */
    public void revoke(CaProvider caProvider, String bundle, String orderId, String reason, String caCredentialRaw) {
        log.info("[SslRevocationService] Routing revocation to ca={}, reason={}", caProvider, reason);
        switch (caProvider) {
            case LETS_ENCRYPT -> leRevocationService.revoke(bundle, reason);
            case DIGICERT -> dcRevocationService.revoke(orderId, reason, caCredentialRaw);
            case GLOBALSIGN -> globalSignRevocationService.revoke(orderId, reason);
            default -> throw new PermanentAgentException("UNSUPPORTED_CA",
                    "Certificate revocation is not supported for CA: " + caProvider
                            + ". Supported: LETS_ENCRYPT, DIGICERT, GLOBALSIGN.");
        }
    }
}
