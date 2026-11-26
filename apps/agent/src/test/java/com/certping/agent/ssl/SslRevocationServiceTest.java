// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.ssl.acme.LetsEncryptRevocationService;
import com.certping.agent.ssl.digicert.DigiCertRevocationService;
import com.certping.agent.ssl.globalsign.GlobalSignRevocationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SslRevocationServiceTest {

    @Mock private LetsEncryptRevocationService leRevocationService;
    @Mock private DigiCertRevocationService dcRevocationService;
    @Mock private GlobalSignRevocationService globalSignRevocationService;

    private SslRevocationService service;

    @BeforeEach
    void setUp() {
        service = new SslRevocationService(
                leRevocationService,
                dcRevocationService,
                globalSignRevocationService);
    }

    @Test
    void revoke_letsEncrypt_delegates() {
        service.revoke(CaProvider.LETS_ENCRYPT, "bundle", "order", "reason", "cred");
        verify(leRevocationService).revoke("bundle", "reason");
    }

    @Test
    void revoke_digicert_delegates() {
        service.revoke(CaProvider.DIGICERT, "bundle", "ord-1", "reason", "apikey");
        verify(dcRevocationService).revoke("ord-1", "reason", "apikey");
    }

    @Test
    void revoke_globalsign_delegates() {
        service.revoke(CaProvider.GLOBALSIGN, "bundle", "ord-2", "reason", "cred");
        verify(globalSignRevocationService).revoke("ord-2", "reason");
    }
}
