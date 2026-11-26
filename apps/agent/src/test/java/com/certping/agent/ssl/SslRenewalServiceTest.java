// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.ssl;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.CaProvider;
import com.certping.agent.model.enums.CertType;
import com.certping.agent.model.message.CertRenewalMessage;
import com.certping.agent.model.message.SanDomainEntry;
import com.certping.agent.service.CredentialAccessService;
import com.certping.agent.ssl.acme.LetsEncryptAcmeService;
import com.certping.agent.ssl.digicert.DigiCertIssuanceService;
import com.certping.agent.ssl.dns.DnsProvider;
import com.certping.agent.ssl.dns.DnsProviderFactory;
import com.certping.agent.ssl.globalsign.GlobalSignIssuanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SslRenewalServiceTest {

    @Mock private LetsEncryptAcmeService leService;
    @Mock private DigiCertIssuanceService digicertService;
    @Mock private GlobalSignIssuanceService globalSignService;
    @Mock private CredentialAccessService credentialAccessService;
    @Mock private DnsProviderFactory dnsProviderFactory;
    @Mock private DnsProvider dnsProvider;

    private SslRenewalService service;

    private static final IssuanceResult RESULT = new IssuanceResult(
            "https://kv.vault.azure.net/secrets/cert-1", null, null,
            "ABCD", "AA:BB", OffsetDateTime.now(), OffsetDateTime.now().plusDays(90), "CN=LE", null,
            "SHA256withRSA", null, null, null, "RSA", 2048, null, null, null, null, null, CertType.DV
    );

    @BeforeEach
    void setUp() {
        service = new SslRenewalService(leService, digicertService, globalSignService,
                credentialAccessService, dnsProviderFactory);
        when(credentialAccessService.readSecret(anyString())).thenReturn("raw-api-token");
        when(dnsProviderFactory.create(anyString(), anyString())).thenReturn(dnsProvider);
    }

    // ── CA provider routing ───────────────────────────────────────────────────

    @Test
    void renew_letsEncrypt_routesToLeService() {
        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        IssuanceResult result = service.renew(buildMsg(CaProvider.LETS_ENCRYPT));

        verify(leService).issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), anyString(), any(), any(), any(), eq(false), any());
        verifyNoInteractions(digicertService, globalSignService);
        assertThat(result.certSecretHandle()).isEqualTo(RESULT.certSecretHandle());
    }

    @Test
    void renew_digicert_routesToDigiCertService() {
        when(digicertService.issue(anyString(), anyString(), any(), any(), any(), anyString(), any(), any(), any()))
                .thenReturn(RESULT);

        service.renew(buildMsg(CaProvider.DIGICERT));

        verify(digicertService).issue(anyString(), anyString(), any(), any(), any(), anyString(), any(), any(), any());
        verifyNoInteractions(leService, globalSignService);
    }

    // ── SAN domain entries ────────────────────────────────────────────────────

    @Test
    void renew_withSanEntries_buildsSanDnsProviders() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        SanDomainEntry sanEntry = new SanDomainEntry();
        sanEntry.setDnsProvider("CLOUDFLARE");
        sanEntry.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/san-cred");
        sanEntry.setPatterns(List.of("*.example.com", "example.com"));
        msg.setSanDomainEntries(List.of(sanEntry));

        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(msg);

        ArgumentCaptor<Map<String, DnsProvider>> mapCaptor = ArgumentCaptor.forClass(Map.class);
        verify(leService).issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), mapCaptor.capture(), any(), any(), any(), any(), eq(false), any());
        assertThat(mapCaptor.getValue()).containsKeys("*.example.com", "example.com");
        verify(credentialAccessService).readSecret("https://kv.vault.azure.net/secrets/san-cred");
        verify(dnsProviderFactory, times(2)).create(anyString(), anyString());
    }

    @Test
    void renew_emptySanEntries_usesEmptyMap() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        msg.setSanDomainEntries(List.of());

        when(leService.issue(anyString(), anyString(), anyString(), eq(false), eq(List.of()), any(), eq(Map.of()), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        IssuanceResult result = service.renew(msg);

        assertThat(result).isNotNull();
        verify(credentialAccessService, times(1)).readSecret(anyString());
    }

    @Test
    void renew_globalsign_routesToGlobalSignService() {
        when(globalSignService.issue(anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(buildMsg(CaProvider.GLOBALSIGN));

        verify(globalSignService).issue(anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), eq(false), any());
        verifyNoInteractions(leService, digicertService);
    }

    @Test
    void renew_letsEncrypt_withPreviousCertSecretHandle_passesAlong() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        msg.setPreviousCertSecretHandle("https://kv.vault.azure.net/secrets/prev");
        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(msg);

        verify(leService).issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(),
                anyString(), any(), any(), eq("https://kv.vault.azure.net/secrets/prev"), eq(false), any());
    }

    @Test
    void renew_sanEntries_nullPatterns_safelySkipped() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        SanDomainEntry e = new SanDomainEntry();
        e.setDnsProvider("CLOUDFLARE");
        e.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/x");
        e.setPatterns(null);
        msg.setSanDomainEntries(List.of(e));
        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(msg);
        verify(credentialAccessService, times(2)).readSecret(anyString());
    }

    @Test
    void renew_sanEntries_blankAndNullPatternEntries_skipped() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        SanDomainEntry e = new SanDomainEntry();
        e.setDnsProvider("CLOUDFLARE");
        e.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/x");
        e.setPatterns(java.util.Arrays.asList(null, "", "  ", "good.example.com"));
        msg.setSanDomainEntries(List.of(e));
        when(leService.issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), any(), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(msg);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, DnsProvider>> mapCap = ArgumentCaptor.forClass(Map.class);
        verify(leService).issue(anyString(), anyString(), anyString(), anyBoolean(), any(), any(), mapCap.capture(), any(), any(), any(), any(), eq(false), any());
        assertThat(mapCap.getValue()).containsOnlyKeys("good.example.com");
    }

    @Test
    void renew_nullSanEntries_usesEmptyMap() {
        CertRenewalMessage msg = buildMsg(CaProvider.LETS_ENCRYPT);
        msg.setSanDomainEntries(null);

        when(leService.issue(anyString(), anyString(), anyString(), eq(false), eq(List.of()), any(), eq(Map.of()), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(RESULT);

        service.renew(msg);
        verify(credentialAccessService, times(1)).readSecret(anyString());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CertRenewalMessage buildMsg(CaProvider ca) {
        CertRenewalMessage msg = new CertRenewalMessage();
        msg.setRequestId("req-2");
        msg.setCorrelationId("corr-2");
        msg.setOrganizationId("organization-1");
        msg.setCertificateXref("xref-1");
        msg.setDomain("example.com");
        msg.setCaProvider(ca);
        msg.setDnsProvider("CLOUDFLARE");
        msg.setDnsCredentialHandle("https://kv.vault.azure.net/secrets/cf-cred");
        msg.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme-acct");
        msg.setCaCredentialHandle("https://kv.vault.azure.net/secrets/ca-cred");
        return msg;
    }
}
