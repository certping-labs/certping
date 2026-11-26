// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.dto.cert;

import com.certmanagement.enums.CaProvider;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertDtoCoverageTest {

    private CertIssuanceRequest.SanDomainEntry san(List<String> patterns) {
        CertIssuanceRequest.SanDomainEntry e = new CertIssuanceRequest.SanDomainEntry();
        e.setPatterns(patterns);
        e.setDnsCredentialXref("cred");
        return e;
    }

    @Test
    void sanWildcardValidForNonGlobalSign() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setCaProvider(CaProvider.LETS_ENCRYPT);
        req.setSanDomainEntries(List.of(san(List.of("*.example.com"))));
        // not GlobalSign -> always valid
        assertThat(req.isSanWildcardValidForCa()).isTrue();
    }

    @Test
    void sanWildcardWithNullEntries() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setCaProvider(CaProvider.GLOBALSIGN);
        req.setSanDomainEntries(null);
        assertThat(req.isSanWildcardValidForCa()).isTrue();
    }

    @Test
    void globalSignRejectsWildcardSan() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setCaProvider(CaProvider.GLOBALSIGN);
        List<String> withNull = new ArrayList<>();
        withNull.add(null);
        withNull.add("*.evil.com");
        req.setSanDomainEntries(List.of(san(List.of("safe.example.com")), san(withNull)));
        assertThat(req.isSanWildcardValidForCa()).isFalse();
    }

    @Test
    void globalSignAcceptsNonWildcardSan() {
        CertIssuanceRequest req = new CertIssuanceRequest();
        req.setCaProvider(CaProvider.GLOBALSIGN);
        req.setSanDomainEntries(List.of(san(List.of("a.example.com")), san(null)));
        assertThat(req.isSanWildcardValidForCa()).isTrue();

        req.setDomain("example.com");
        req.setWildcard(false);
        req.setSan(true);
        req.setDnsCredentialXref("c");
        assertThat(req.getDomain()).isEqualTo("example.com");
    }

    @Test
    void convertToAutomatedRequest() {
        ConvertToAutomatedRequest r = new ConvertToAutomatedRequest();
        ConvertToAutomatedRequest.DnsCredentialMapping m = new ConvertToAutomatedRequest.DnsCredentialMapping();
        m.setDomain("a.com");
        m.setCredentialXref("x");
        r.setDnsMappings(List.of(m));
        r.setDeploymentTargets(List.of("t"));
        r.setActivationMode(ConvertToAutomatedRequest.ActivationMode.IMMEDIATE);
        r.setInFlightPolicy(ConvertToAutomatedRequest.InFlightPolicy.WAIT);

        assertThat(r.getDnsMappings()).hasSize(1);
        assertThat(m.getDomain()).isEqualTo("a.com");
        assertThat(m.getCredentialXref()).isEqualTo("x");
        assertThat(r.getDeploymentTargets()).containsExactly("t");
        assertThat(r.getActivationMode()).isEqualTo(ConvertToAutomatedRequest.ActivationMode.IMMEDIATE);
        assertThat(r.getInFlightPolicy()).isEqualTo(ConvertToAutomatedRequest.InFlightPolicy.WAIT);

        for (var a : ConvertToAutomatedRequest.ActivationMode.values()) {
            assertThat(ConvertToAutomatedRequest.ActivationMode.valueOf(a.name())).isSameAs(a);
        }
        for (var p : ConvertToAutomatedRequest.InFlightPolicy.values()) {
            assertThat(ConvertToAutomatedRequest.InFlightPolicy.valueOf(p.name())).isSameAs(p);
        }
    }
}
