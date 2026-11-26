// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.messaging.model.AgentInfo;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AgentInfoSanitizerTest {

    @Test
    void keepsWellFormedValues() {
        AgentInfo clean = AgentInfoSanitizer.sanitize(AgentInfo.builder()
                .version(" 0.2.0-rc.1 ").hostname("ip-10-0-0-1.ec2.internal").os("Mac OS X aarch64")
                .javaVersion("25.0.1+9").secretStore("gcp_secret_manager").maxConcurrentJobs(8)
                .proxyConfigured(true).bundled(false)
                .capabilities(AgentInfo.Capabilities.builder()
                        .deploymentTargets(List.of("AZURE_KEYVAULT", "AZURE_KEYVAULT", "KUBERNETES_SECRETS"))
                        .build())
                .build());

        assertThat(clean.getVersion()).isEqualTo("0.2.0-rc.1");
        assertThat(clean.getHostname()).isEqualTo("ip-10-0-0-1.ec2.internal");
        assertThat(clean.getOs()).isEqualTo("Mac OS X aarch64");
        assertThat(clean.getJavaVersion()).isEqualTo("25.0.1+9");
        assertThat(clean.getSecretStore()).isEqualTo("GCP_SECRET_MANAGER");
        assertThat(clean.getMaxConcurrentJobs()).isEqualTo(8);
        assertThat(clean.getCapabilities().getDeploymentTargets())
                .containsExactly("AZURE_KEYVAULT", "KUBERNETES_SECRETS");
        assertThat(clean.getCapabilities().getDiscoveryTargets()).isEmpty();
    }

    @Test
    void dropsMalformedAndSecretLookingValues() {
        AgentInfo clean = AgentInfoSanitizer.sanitize(AgentInfo.builder()
                .version("cpa_abcdefghijklmnopqrstuvwxyz0123456789")
                .hostname("user:pass@host")
                .os("<script>alert(1)</script>")
                .javaVersion("-----BEGIN PRIVATE KEY-----")
                .secretStore("VAULT")
                .maxConcurrentJobs(0)
                .capabilities(AgentInfo.Capabilities.builder()
                        .dnsProviders(Arrays.asList("CLOUDFLARE", null, "token=abc", "cpa_X", "lower"))
                        .build())
                .build());

        assertThat(clean.getVersion()).isNull();
        assertThat(clean.getHostname()).isNull();
        assertThat(clean.getOs()).isNull();
        assertThat(clean.getJavaVersion()).isNull();
        assertThat(clean.getSecretStore()).isNull();
        assertThat(clean.getMaxConcurrentJobs()).isNull();
        assertThat(clean.getCapabilities().getDnsProviders()).containsExactly("CLOUDFLARE");
    }

    @Test
    void nullStaysNull() {
        assertThat(AgentInfoSanitizer.sanitize(null)).isNull();
    }
}
