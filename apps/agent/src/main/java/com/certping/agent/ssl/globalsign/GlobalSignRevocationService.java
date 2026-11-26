// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.globalsign;

import com.certping.agent.exception.PermanentAgentException;
import tools.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class GlobalSignRevocationService {

    private final GlobalSignAtlasClient atlasClient;

    public void revoke(String serial, String reason) {
        if (serial == null || serial.isBlank()) {
            throw new PermanentAgentException("MISSING_ORDER_ID",
                    "GlobalSign revocation requires certificate serial in orderId field");
        }

        JsonNode current = atlasClient.getCertificate(serial);
        String status = current.path("status").asString("");
        if ("REVOKED".equalsIgnoreCase(status)) {
            log.info("[GlobalSignRevocation] Certificate {} already revoked - treating as success", serial);
            return;
        }

        atlasClient.revokeCertificate(serial, reason);
        log.info("[GlobalSignRevocation] Certificate {} revoked successfully", serial);
    }
}