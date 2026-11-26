// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.scep.ca;

import com.certping.agent.config.AgentProperties;
import com.certping.agent.exception.AgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.scep.CaUnavailableException;
import com.certping.agent.scep.RaIdentity;
import com.certping.agent.secrets.SecretStore;
import com.certping.agent.ssl.smallstep.SmallstepSignResult;
import com.certping.agent.ssl.smallstep.SmallstepRevocationService;
import com.certping.agent.ssl.smallstep.SmallstepSigningService;
import tools.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

@RequiredArgsConstructor
public class SmallstepScepCaBackend implements ScepCaBackend {
    private final SmallstepSigningService smallstep;
    private final SmallstepRevocationService revocationService;
    private final SecretStore secretStore;
    private final AgentProperties properties;
    private final ObjectMapper objectMapper;
    private RaIdentity ra;

    @PostConstruct
    void loadRa() throws Exception {
        ra = RaIdentity.fromSecret(secretStore, objectMapper,
                properties.getScep().getCa().getRaKeystoreHandle());
    }

    @Override
    public IssuedCertificate sign(PKCS10CertificationRequest csr, Duration validity) throws CaException {
        try {
            SmallstepSignResult result = smallstep.sign(csr, validity);
            String authority = result.authorityName() == null || result.authorityName().isBlank()
                    ? result.leaf().getIssuerX500Principal().getName() : result.authorityName();
            return new IssuedCertificate(result.chain(), null, CaProvider.SMALLSTEP,
                    authority, result.provisionerName());
        } catch (TransientAgentException exception) {
            throw new CaUnavailableException(exception.getMessage(), exception);
        } catch (AgentException exception) {
            throw new CaException(exception.getMessage(), exception);
        } catch (Exception exception) {
            throw new CaException("Smallstep signing failed: " + exception.getMessage(), exception);
        }
    }

    @Override
    public void assertRenewalAllowed(X509Certificate priorCertificate) throws CaException {
        try {
            revocationService.assertRenewalAllowed(priorCertificate);
        } catch (TransientAgentException exception) {
            throw new CaUnavailableException(exception.getMessage(), exception);
        } catch (AgentException exception) {
            throw new CaException(exception.getMessage(), exception);
        }
    }

    @Override public X509Certificate getRaCertificate() { return ra.cert(); }
    @Override public PrivateKey getRaPrivateKey() { return ra.key(); }
    @Override public List<X509Certificate> getCaChain() { return ra.caChain(); }
}
