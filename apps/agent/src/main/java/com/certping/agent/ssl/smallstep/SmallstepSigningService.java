// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.smallstep;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.PermanentAgentException;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class SmallstepSigningService {
    private final SmallstepClient client;
    private final AgentProperties properties;

    public SmallstepSignResult sign(PKCS10CertificationRequest csr, Duration validity) {
        if (!properties.getSmallstep().isEnabled()) {
            throw new PermanentAgentException("SMALLSTEP_DISABLED",
                    "Smallstep signing is disabled. Set agent.smallstep.enabled=true.");
        }
        return client.sign(csr, validity);
    }
    public String probeVersion() { return client.probeVersion(); }
    public String connectedEndpoint() { return client.connectedEndpoint(); }
    public String provisionerName() { return client.provisionerName(); }
    public String authorityName() { return client.authorityName(); }
}
