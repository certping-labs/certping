// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.RenewalScheduleEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.CertificateStatus;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.ServiceUnavailableException;
import com.certmanagement.messaging.CertAgentPublisher;
import com.certmanagement.messaging.model.CertIssuanceCommand;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AkamaiSpecialIssuanceServiceTest {

    @Mock private CertificateRepository      certificateRepository;
    @Mock private RenewalScheduleRepository  renewalScheduleRepository;
    @Mock private CredentialReferenceService credentialReferenceService;
    @Mock private CertAgentPublisher         publisher;
    @Mock private com.certmanagement.service.OrgTypeResolver orgTypeResolver;

    private AkamaiSpecialIssuanceService service;

    private static final Long   ORG_ID     = 1L;
    private static final Long   UDC_ID     = 2L;
    private static final Long   CONFIG_ID  = 3L;
    private static final String CERT_XREF  = "cert-regular-abc";
    private static final String DNS_CRED_XREF  = "cred-dns-cf";
    private static final String AKAMAI_CRED_KV = "https://kv.vault.azure.net/secrets/akamai-cred";

    @BeforeEach
    void setUp() {
        service = new AkamaiSpecialIssuanceService(
                certificateRepository, renewalScheduleRepository,
                credentialReferenceService, publisher, orgTypeResolver,
                com.certmanagement.testing.Transactions.manager());
        org.mockito.Mockito.lenient().when(orgTypeResolver.resolve(org.mockito.ArgumentMatchers.any(Long.class)))
                .thenReturn("B2B");
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void triggerAkamaiSpecialIssuance_happyPath_persistsCertAndScheduleAsPending() {
        CertificateEntity regularCert = buildRegularCert();
        RenewalScheduleEntity schedule = buildSchedule();
        DomainCredentialConfigEntity credConfig = buildCredConfig();
        CredentialReferenceEntity akamaiCred = buildAkamaiCred();

        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        service.triggerAkamaiSpecialIssuance(ORG_ID, regularCert, schedule, credConfig, akamaiCred);

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());
        CertificateEntity saved = certCaptor.getValue();

        assertThat(saved.getStatus()).isEqualTo(CertificateStatus.PENDING.name());
        assertThat(saved.getSpecialCertificateType()).isEqualTo("AKAMAI_CPS");
        assertThat(saved.getUserDomainCertId()).isEqualTo(UDC_ID);
        assertThat(saved.getCaProvider()).isEqualTo(CaProvider.LETS_ENCRYPT);
    }

    @Test
    void triggerAkamaiSpecialIssuance_happyPath_persistsScheduleAsDisabled() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                buildCredConfig(), buildAkamaiCred());

        ArgumentCaptor<RenewalScheduleEntity> rsCaptor = ArgumentCaptor.forClass(RenewalScheduleEntity.class);
        verify(renewalScheduleRepository).save(rsCaptor.capture());
        RenewalScheduleEntity saved = rsCaptor.getValue();

        assertThat(saved.getEnabled()).isFalse();
        assertThat(saved.getDomainCredentialConfigId()).isEqualTo(CONFIG_ID);
        assertThat(saved.getRenewalEligibleAt()).isAfter(OffsetDateTime.now(ZoneOffset.UTC).plusMonths(10));
    }

    @Test
    void triggerAkamaiSpecialIssuance_happyPath_publishesCommandWithAkamaiFields() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                buildCredConfig(), buildAkamaiCred());

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        CertIssuanceCommand cmd = cmdCaptor.getValue();

        assertThat(cmd.getSpecialCertType()).isEqualTo("AKAMAI_CPS");
        assertThat(cmd.getSpecialDeploymentCredHandle()).isEqualTo(AKAMAI_CRED_KV);
        assertThat(cmd.getDomain()).isEqualTo("example.com");
        assertThat(cmd.getOrganizationId()).isEqualTo(ORG_ID.toString());
        assertThat(cmd.getCaProvider()).isEqualTo(CaProvider.LETS_ENCRYPT);
    }

    @Test
    void triggerAkamaiSpecialIssuance_happyPath_commandCertXrefMatchesSavedCert() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                buildCredConfig(), buildAkamaiCred());

        ArgumentCaptor<CertificateEntity> certCaptor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(certCaptor.capture());

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());

        assertThat(cmdCaptor.getValue().getCertificateXref())
                .isEqualTo(certCaptor.getValue().getCertificateXref());
    }

    // ── Failure: no DNS credential configured ─────────────────────────────────

    @Test
    void triggerAkamaiSpecialIssuance_noDnsConfig_throwsBadRequest() {
        DomainCredentialConfigEntity credConfigNoDns = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(Map.of())
                .build();

        assertThatThrownBy(() ->
                service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                        credConfigNoDns, buildAkamaiCred()))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("no DNS credential configured");

        verify(certificateRepository, never()).save(any());
        verify(publisher, never()).publishIssuance(any());
    }

    @Test
    void triggerAkamaiSpecialIssuance_nullDnsConfig_throwsBadRequest() {
        DomainCredentialConfigEntity credConfigNullDns = DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .dnsConfig(null)
                .build();

        assertThatThrownBy(() ->
                service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                        credConfigNullDns, buildAkamaiCred()))
                .isInstanceOf(BadRequestException.class);

        verify(publisher, never()).publishIssuance(any());
    }

    // ── Failure: publish fails ────────────────────────────────────────────────

    @Test
    void triggerAkamaiSpecialIssuance_publishFails_marksCertFailedAndThrows() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());
        doThrow(new RuntimeException("queue down")).when(publisher).publishIssuance(any());

        // markFailed does findByCertificateXref to update the cert
        when(certificateRepository.findByCertificateXref(any())).thenAnswer(inv -> {
            CertificateEntity c = CertificateEntity.builder()
                    .certificateXref(inv.getArgument(0))
                    .status(CertificateStatus.PENDING.name())
                    .build();
            return Optional.of(c);
        });

        assertThatThrownBy(() ->
                service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), buildSchedule(),
                        buildCredConfig(), buildAkamaiCred()))
                .isInstanceOf(ServiceUnavailableException.class)
                .hasMessageContaining("FAILED");

        // save called at least twice: once for initial persist, once for markFailed
        verify(certificateRepository, atLeast(2)).save(any());
        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository, atLeast(2)).save(captor.capture());
        assertThat(captor.getAllValues())
                .anySatisfy(c -> assertThat(c.getStatus()).isEqualTo(CertificateStatus.FAILED.name()));
    }

    // ── persistSpecialCertAndSchedule ─────────────────────────────────────────

    @Test
    void persistSpecialCertAndSchedule_copiesSanDomainsFromRegularCert() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        CertificateEntity regularCert = buildRegularCert();
        regularCert.setSanDomains(new String[]{"*.example.com", "www.example.com"});

        service.triggerAkamaiSpecialIssuance(ORG_ID, regularCert, buildSchedule(),
                buildCredConfig(), buildAkamaiCred());

        ArgumentCaptor<CertificateEntity> captor = ArgumentCaptor.forClass(CertificateEntity.class);
        verify(certificateRepository).save(captor.capture());
        assertThat(captor.getValue().getSanDomains()).containsExactly("*.example.com", "www.example.com");
    }

    @Test
    void persistSpecialCertAndSchedule_copiesAcmeAccountHandleFromSchedule() {
        when(credentialReferenceService.getByXref(ORG_ID, DNS_CRED_XREF)).thenReturn(buildDnsCred());

        RenewalScheduleEntity schedule = buildSchedule();
        schedule.setAcmeAccountHandle("https://kv.vault.azure.net/secrets/acme-acct");

        service.triggerAkamaiSpecialIssuance(ORG_ID, buildRegularCert(), schedule,
                buildCredConfig(), buildAkamaiCred());

        ArgumentCaptor<CertIssuanceCommand> cmdCaptor = ArgumentCaptor.forClass(CertIssuanceCommand.class);
        verify(publisher).publishIssuance(cmdCaptor.capture());
        assertThat(cmdCaptor.getValue().getAcmeAccountHandle())
                .isEqualTo("https://kv.vault.azure.net/secrets/acme-acct");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CertificateEntity buildRegularCert() {
        UserDomainCertEntity udc = UserDomainCertEntity.builder()
                .id(UDC_ID).organizationId(ORG_ID).domain("example.com").build();
        return CertificateEntity.builder()
                .certificateXref(CERT_XREF)
                .userDomainCertId(UDC_ID)
                .userDomainCert(udc)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .wildcard(false)
                .san(false)
                .status(CertificateStatus.ACTIVE.name())
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .build();
    }

    private RenewalScheduleEntity buildSchedule() {
        return RenewalScheduleEntity.builder()
                .certificateXref(CERT_XREF)
                .domainCredentialConfigId(CONFIG_ID)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .certSecretHandle("https://kv.vault.azure.net/secrets/cert")
                .validTo(OffsetDateTime.now(ZoneOffset.UTC).plusDays(90))
                .renewalEligibleAt(OffsetDateTime.now(ZoneOffset.UTC).plusDays(60))
                .enabled(true)
                .build();
    }

    private DomainCredentialConfigEntity buildCredConfig() {
        return DomainCredentialConfigEntity.builder()
                .id(CONFIG_ID)
                .userDomainCertId(UDC_ID)
                .dnsConfig(Map.of("example.com", DNS_CRED_XREF))
                .deploymentTargets(List.of("cred-akamai"))
                .build();
    }

    private CredentialReferenceEntity buildAkamaiCred() {
        return CredentialReferenceEntity.builder()
                .credentialXref("cred-akamai")
                .provider("AKAMAI_CPS")
                .secretHandle(AKAMAI_CRED_KV)
                .status("ACTIVE")
                .type("DEPLOYMENT")
                .build();
    }

    private CredentialReferenceEntity buildDnsCred() {
        return CredentialReferenceEntity.builder()
                .credentialXref(DNS_CRED_XREF)
                .provider("CLOUDFLARE")
                .secretHandle("https://kv.vault.azure.net/secrets/dns-cred")
                .status("ACTIVE")
                .type("DNS")
                .build();
    }
}
