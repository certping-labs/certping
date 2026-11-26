// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl.dns;

import com.certping.agent.exception.PermanentAgentException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DnsProviderFactoryTest {

    private DnsProviderFactory factory;

    @BeforeEach
    void setUp() {
        factory = new DnsProviderFactory(() -> "203.0.113.10");
    }

    // ── Cloudflare ────────────────────────────────────────────────────────────

    @Test
    void createIfConfigured_withoutAHandle_readsNothingAndReturnsNull() {
        assertThat(factory.createIfConfigured("CLOUDFLARE", " ", handle -> {
            throw new AssertionError("no secret may be read without a handle");
        })).isNull();
        assertThat(factory.createIfConfigured("CLOUDFLARE", null, handle -> {
            throw new AssertionError("no secret may be read without a handle");
        })).isNull();
    }

    @Test
    void createIfConfigured_withAHandle_buildsTheProviderFromItsSecret() {
        DnsProvider provider = factory.createIfConfigured("CLOUDFLARE", "kv://dns",
                handle -> "kv://dns".equals(handle) ? "{\"apiToken\":\"my-cf-api-token\"}" : null);

        assertThat(provider).isInstanceOf(CloudflareDnsProvider.class);
    }

    @Test
    void create_cloudflare_returnsCloudflareProvider() {
        DnsProvider provider = factory.create("CLOUDFLARE", "{\"apiToken\":\"my-cf-api-token\"}");
        assertThat(provider).isInstanceOf(CloudflareDnsProvider.class);
    }

    @Test
    void create_cloudflare_caseInsensitive_returnsCloudflareProvider() {
        DnsProvider provider = factory.create("cloudflare", "{\"apiToken\":\"my-cf-api-token\"}");
        assertThat(provider).isInstanceOf(CloudflareDnsProvider.class);
    }

    @Test
    void create_cloudflare_blankApiToken_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("CLOUDFLARE", "{\"apiToken\":\"\"}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_cloudflare_missingApiToken_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("CLOUDFLARE", "{}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_cloudflare_bareTokenStringNotAccepted_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("CLOUDFLARE", "raw-bare-token"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── AWS Route53 ───────────────────────────────────────────────────────────

    @Test
    void create_awsRoute53_returnsRoute53Provider() {
        String json = "{\"accessKeyId\":\"AKIA123\",\"secretAccessKey\":\"secret456\"}";
        DnsProvider provider = factory.create("AWS_ROUTE53", json);
        assertThat(provider).isInstanceOf(AwsRoute53DnsProvider.class);
    }

    @Test
    void create_awsRoute53_missingSecretAccessKey_throwsDnsCredentialInvalid() {
        String json = "{\"accessKeyId\":\"AKIA123\"}";
        assertThatThrownBy(() -> factory.create("AWS_ROUTE53", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_awsRoute53_blankAccessKeyId_throwsDnsCredentialInvalid() {
        String json = "{\"accessKeyId\":\"\",\"secretAccessKey\":\"secret456\"}";
        assertThatThrownBy(() -> factory.create("AWS_ROUTE53", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_awsRoute53_invalidJson_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("AWS_ROUTE53", "not-json"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── GoDaddy ───────────────────────────────────────────────────────────────

    @Test
    void create_godaddy_returnsGoDaddyProvider() {
        String json = "{\"apiKey\":\"key1\",\"apiSecret\":\"secret1\"}";
        DnsProvider provider = factory.create("GODADDY", json);
        assertThat(provider).isInstanceOf(GoDaddyDnsProvider.class);
    }

    @Test
    void create_godaddy_blankApiKey_throwsDnsCredentialInvalid() {
        String json = "{\"apiKey\":\"\",\"apiSecret\":\"secret1\"}";
        assertThatThrownBy(() -> factory.create("GODADDY", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_godaddy_blankApiSecret_throwsDnsCredentialInvalid() {
        String json = "{\"apiKey\":\"key1\",\"apiSecret\":\"   \"}";
        assertThatThrownBy(() -> factory.create("GODADDY", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── Name.com ──────────────────────────────────────────────────────────────

    @Test
    void create_namedotcom_returnsNameDotComProvider() {
        String json = "{\"username\":\"user1\",\"apiToken\":\"token1\"}";
        DnsProvider provider = factory.create("NAMEDOTCOM", json);
        assertThat(provider).isInstanceOf(NameDotComDnsProvider.class);
    }

    @Test
    void create_namedotcom_blankUsername_throwsDnsCredentialInvalid() {
        String json = "{\"username\":\"\",\"apiToken\":\"token1\"}";
        assertThatThrownBy(() -> factory.create("NAMEDOTCOM", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_namedotcom_blankApiToken_throwsDnsCredentialInvalid() {
        String json = "{\"username\":\"user1\",\"apiToken\":\"   \"}";
        assertThatThrownBy(() -> factory.create("NAMEDOTCOM", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── Hostinger ─────────────────────────────────────────────────────────────

    @Test
    void create_hostinger_returnsHostingerProvider() {
        DnsProvider provider = factory.create("HOSTINGER", "{\"apiToken\":\"hg-token\"}");
        assertThat(provider).isInstanceOf(HostingerDnsProvider.class);
    }

    @Test
    void create_hostinger_caseInsensitive_returnsHostingerProvider() {
        DnsProvider provider = factory.create("hostinger", "{\"apiToken\":\"hg-token\"}");
        assertThat(provider).isInstanceOf(HostingerDnsProvider.class);
    }

    @Test
    void create_hostinger_blankApiToken_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("HOSTINGER", "{\"apiToken\":\"\"}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_hostinger_missingApiToken_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("HOSTINGER", "{}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── Namecheap ────────────────────────────────────────────────────────────

    @Test
    void create_namecheap_returnsNamecheapProvider() {
        String json = "{\"apiUser\":\"api-user\",\"apiKey\":\"api-key\",\"username\":\"user\"}";
        DnsProvider provider = factory.create("NAMECHEAP", json);
        assertThat(provider).isInstanceOf(NamecheapDnsProvider.class);
    }

    @Test
    void create_namecheap_caseInsensitive_returnsNamecheapProvider() {
        String json = "{\"apiUser\":\"api-user\",\"apiKey\":\"api-key\",\"username\":\"user\"}";
        DnsProvider provider = factory.create("namecheap", json);
        assertThat(provider).isInstanceOf(NamecheapDnsProvider.class);
    }

    @Test
    void create_namecheap_missingApiUser_throwsDnsCredentialInvalid() {
        String json = "{\"apiKey\":\"api-key\",\"username\":\"user\"}";
        assertThatThrownBy(() -> factory.create("NAMECHEAP", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_namecheap_blankClientIpEnv_throwsDnsCredentialInvalid() {
        DnsProviderFactory missingClientIpFactory = new DnsProviderFactory(() -> " ");
        String json = "{\"apiUser\":\"api-user\",\"apiKey\":\"api-key\",\"username\":\"user\"}";

        assertThatThrownBy(() -> missingClientIpFactory.create("NAMECHEAP", json))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── CertPing DNS (POWERDNS is a legacy alias) ─────────────────────────────

    @Test
    void create_certping_defaultsToTheTokenApi() {
        DnsProvider provider = factory.create("certping", "{\"apiKey\":\"cpk_live_x\"}");

        assertThat(provider).isInstanceOf(CertPingDnsProvider.class);
        assertThat(ReflectionTestUtils.getField(provider, "apiUrl"))
                .isEqualTo(CertPingDnsProvider.DEFAULT_API_BASE);
    }

    @Test
    void create_powerdns_isAnAliasForCertPing() {
        DnsProvider provider = factory.create("POWERDNS", "{\"apiKey\":\"cpk_live_x\"}");

        assertThat(provider).isInstanceOf(CertPingDnsProvider.class);
        assertThat(ReflectionTestUtils.getField(provider, "apiUrl"))
                .isEqualTo(CertPingDnsProvider.DEFAULT_API_BASE);
    }

    @Test
    void create_powerdns_caseInsensitive_returnsCertPingProvider() {
        DnsProvider provider = factory.create("powerdns", "{\"apiKey\":\"cpk_live_x\"}");
        assertThat(provider).isInstanceOf(CertPingDnsProvider.class);
    }

    @Test
    void create_credentialApiUrl_isIgnored_envWins() {
        DnsProviderFactory envFactory = new DnsProviderFactory(
                () -> null, () -> "https://dns.example.test/api/v1/domains/token-api");
        String json = "{\"apiKey\":\"k\",\"apiUrl\":\"https://attacker.test/t\"}";

        for (String name : new String[] {"CERTPING", "POWERDNS"}) {
            assertThat(ReflectionTestUtils.getField(envFactory.create(name, json), "apiUrl"))
                    .as(name)
                    .isEqualTo("https://dns.example.test/api/v1/domains/token-api");
        }
    }

    @Test
    void create_credentialApiUrl_isIgnored_defaultWithoutEnv() {
        String json = "{\"apiKey\":\"k\",\"apiUrl\":\"http://192.0.2.10:8081/api/v1\"}";

        for (String name : new String[] {"CERTPING", "POWERDNS"}) {
            assertThat(ReflectionTestUtils.getField(factory.create(name, json), "apiUrl"))
                    .as(name)
                    .isEqualTo(CertPingDnsProvider.DEFAULT_API_BASE);
        }
    }

    @Test
    void create_certping_blankApiKey_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("CERTPING", "{\"apiKey\":\" \"}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    @Test
    void create_powerdns_blankApiKey_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("POWERDNS", "{\"apiKey\":\"\"}"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }

    // ── Unknown / null ────────────────────────────────────────────────────────

    @Test
    void create_unknownProvider_throwsDnsProviderUnknown() {
        assertThatThrownBy(() -> factory.create("UNKNOWN_DNS", "some-cred"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_UNKNOWN"));
    }

    @Test
    void create_nullProvider_throwsDnsProviderUnknown() {
        assertThatThrownBy(() -> factory.create(null, "some-cred"))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_PROVIDER_UNKNOWN"));
    }

    @Test
    void create_nullCredential_throwsDnsCredentialInvalid() {
        assertThatThrownBy(() -> factory.create("CLOUDFLARE", null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DNS_CREDENTIAL_INVALID"));
    }
}
