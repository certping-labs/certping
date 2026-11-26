// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.audit.AuditActorType;
import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventRow;
import com.certmanagement.audit.AuditOutcome;
import com.certmanagement.audit.AuditReason;
import com.certmanagement.audit.AuditReasons;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditVisibility;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DomainCredentialConfigEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.dto.credconfig.AddDeploymentTargetRequest;
import com.certmanagement.exception.CredentialRejectedException;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CredentialReferenceRepository;
import com.certmanagement.repository.DomainCredentialConfigRepository;
import com.certmanagement.repository.OrganizationRepository;
import com.certmanagement.repository.RenewalScheduleRepository;
import com.certmanagement.repository.UserDomainCertRepository;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.audit.CredentialAuditRecorder;
import com.certmanagement.service.deployment.CertDeploymentConfigService;
import com.certmanagement.service.deployment.config.DeploymentScopeValidatorRegistry;
import com.certmanagement.service.lifecycle.FeatureLifecycleLock;
import com.certmanagement.util.UserFacingErrorMessages;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The credential and deployment-target services write their audit rows through the real
 * {@link CredentialAuditRecorder} and catalog: what each row says, and that no secret (pasted credential details,
 * the secret store location, the scope configuration, a deployment plan) is ever part of one, by value.
 */
class CredentialAuditFlowTest {

    private static final long ORG = 42L;
    private static final String API_TOKEN = "cf-live-token-7f3a9c";
    private static final String CLIENT_SECRET = "az-client-secret-Q8~zz";
    private static final String HANDLE = "https://example-vault-agent-prod.vault.azure.net/secrets/org-42-cred";
    private static final String OWN_HANDLE = "https://acme-vault.vault.azure.net/secrets/app-gw-sp";
    private static final String LISTENER_ARN = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:listener/app/x";

    private final ObjectMapper json = JsonMapper.builderWithJackson2Defaults().build();
    private final AuditRecorder recorder = mock(AuditRecorder.class);
    private final CredentialAuditRecorder audit = new CredentialAuditRecorder(recorder);
    private final CredentialReferenceRepository credentials = mock(CredentialReferenceRepository.class);
    private final OrganizationRepository organizations = mock(OrganizationRepository.class);
    private final AgentSecretWriter secretWriter = mock(AgentSecretWriter.class);
    private final DomainCredentialConfigRepository configs = mock(DomainCredentialConfigRepository.class);
    private final CertDeploymentConfigRepository deploymentConfigs = mock(CertDeploymentConfigRepository.class);
    private final UserDomainCertRepository domains = mock(UserDomainCertRepository.class);

    private CredentialReferenceService service;
    private DomainCredentialConfigService configService;

    @BeforeEach
    void setUp() {
        GatewayRequestContext.set(7, String.valueOf(ORG), "req-1", "alice@acme.test");
        service = new CredentialReferenceService(credentials, configs, deploymentConfigs, organizations,
                mock(KubernetesDeploymentConfigValidator.class), mock(DeploymentScopeValidatorRegistry.class), json,
                new CredJsonDispatcher(json), secretWriter, mock(RenewalScheduleRepository.class),
                mock(FeatureLifecycleLock.class), audit);
        configService = new DomainCredentialConfigService(configs, domains, service,
                mock(CertDeploymentConfigService.class), mock(RenewalScheduleRepository.class),
                mock(FeatureLifecycleLock.class), credentials, audit);
        when(organizations.existsById(ORG)).thenReturn(true);
        when(credentials.save(any(CredentialReferenceEntity.class))).thenAnswer(call -> {
            CredentialReferenceEntity saved = call.getArgument(0);
            if (saved.getId() == null) {
                saved.setId(501L);
            }
            return saved;
        });
        when(secretWriter.isAvailable()).thenReturn(true);
        when(secretWriter.buildSecretName(any(), anyString())).thenReturn("org-42-cred");
        when(secretWriter.writeSecret(anyString(), anyString())).thenReturn(HANDLE);
    }

    @AfterEach
    void clear() {
        GatewayRequestContext.clear();
    }

    @Test
    void aPastedDnsCredentialIsRecordedWithoutItsToken() throws Exception {
        service.registerDns(ORG, "CLOUDFLARE", "Prod DNS", null, json.readTree("{\"apiToken\":\"" + API_TOKEN + "\"}"), null);

        AuditEventRow row = onlyRow();
        assertThat(row.event()).isEqualTo("credential.created");
        assertThat(row.visibility()).isEqualTo(AuditVisibility.CUSTOMER);
        assertThat(row.actorType()).isEqualTo(AuditActorType.USER);
        assertThat(row.organizationId()).isEqualTo(ORG);
        assertThat(row.summary()).isEqualTo("Added the Cloudflare DNS credential 'Prod DNS'");
        assertThat(row.resourceName()).isEqualTo("Prod DNS");
        assertThat(row.resourceRef()).startsWith("cred-");
        assertThat(row.details().attributes()).containsExactly(Map.entry("credentialType", "DNS"),
                Map.entry("storedIn", "CERTPING"));
        assertNoSecret(row);
    }

    @Test
    void aDeploymentCredentialInTheCustomersOwnVaultKeepsNoLocation() {
        service.registerDeployment(ORG, "AZURE_APP_GW", "App gateway", OWN_HANDLE,
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"subscriptionId\":\"sub-1\"}", null);

        AuditEventRow row = onlyRow();
        assertThat(row.summary()).isEqualTo("Added the Azure Application Gateway deployment credential 'App gateway'");
        assertThat(row.details().attributes()).containsEntry("storedIn", "OWN_STORE")
                .containsEntry("authMode", "SERVICE_PRINCIPAL");
        assertThat(rowText(row)).doesNotContain("acme-vault").doesNotContain("sub-1");
    }

    @Test
    void aRotatedSecretIsNamedNeverValued() throws Exception {
        CredentialReferenceEntity existing = credential("cred-9", "DEPLOYMENT", "AZURE_KV", "Discovery vault");
        existing.setSecretHandle(HANDLE);
        when(credentials.findByCredentialXrefAndOrganizationId("cred-9", ORG)).thenReturn(Optional.of(existing));

        service.updateCredential(ORG, "cred-9", null, "{\"allowedVaults\":[\"kv-prod\"]}",
                json.readTree("{\"clientSecret\":\"" + CLIENT_SECRET + "\",\"clientId\":\"c\",\"tenantId\":\"t\"}"));

        AuditEventRow row = onlyRow();
        assertThat(row.event()).isEqualTo("credential.updated");
        assertThat(row.summary()).isEqualTo("Changed the Azure Key Vault deployment credential 'Discovery vault'");
        assertThat(row.details().changes()).containsExactly(new AuditChange("credJson", null, null),
                new AuditChange("configJson", null, null));
        assertNoSecret(row);
        assertThat(rowText(row)).doesNotContain("kv-prod");
    }

    @Test
    void aDeletedCredentialSaysHowManyConfigurationsLostIt() {
        CredentialReferenceEntity existing = credential("cred-3", "DNS", "GODADDY", "Shop DNS");
        when(credentials.findByCredentialXrefAndOrganizationId("cred-3", ORG)).thenReturn(Optional.of(existing));
        when(configs.removeCredentialXref("cred-3")).thenReturn(2);
        when(deploymentConfigs.softDeleteByCredentialXref("cred-3")).thenReturn(1);

        service.delete(ORG, "cred-3");

        AuditEventRow row = onlyRow();
        assertThat(row.summary()).isEqualTo("Deleted the GoDaddy DNS credential 'Shop DNS'");
        assertThat(row.details().attributes()).containsEntry("configurationsCleared", "3");
    }

    @Test
    void refusalsCarryTheCodeTheTrailRendersNeverTheMessage() {
        CredentialReferenceEntity inUse = credential("cred-4", "DNS", "CLOUDFLARE", "In use");
        when(credentials.findByCredentialXrefAndOrganizationId("cred-4", ORG)).thenReturn(Optional.of(inUse));
        when(credentials.countActiveCertsReferencingCredential("cred-4")).thenReturn(2L);

        Throwable badHandle = catchThrown(() -> service.registerDns(ORG, "CLOUDFLARE", "x", "bad\u0001handle", null, null));
        Throwable badDetails = catchThrown(() -> service.registerDns(ORG, "CERTPING", "x", null,
                json.createObjectNode().put("apiKey", " "), null));
        Throwable stillUsed = catchThrown(() -> service.delete(ORG, "cred-4"));

        assertThat(List.of(badHandle, badDetails, stillUsed)).allSatisfy(t -> assertThat(t).isInstanceOf(CredentialRejectedException.class));
        assertThat(AuditReasons.of(badHandle).code()).isEqualTo("KV_URI_INVALID");
        assertThat(AuditReasons.of(stillUsed).code()).isEqualTo("CREDENTIAL_IN_USE");
        assertThat(AuditReasons.of(badDetails).code()).isEqualTo("CREDENTIAL_DETAILS_INVALID");
        verify(recorder, never()).record(any());
        for (String code : List.of("KV_URI_INVALID", "CREDENTIAL_IN_USE", "CREDENTIAL_DETAILS_INVALID",
                "CREDENTIAL_TYPE_MISMATCH", "CREDENTIAL_NOT_ACTIVE", "AZURE_PERMISSION_DENIED", "DNS_AUTH_FAILED")) {
            String message = AuditReason.of(code).message("req-1");
            assertThat(message).as(code).isNotBlank().doesNotContain(code).doesNotContain("vault.azure.net");
        }
        assertThat(AuditReason.of("KV_URI_INVALID").message(null)).isEqualTo(UserFacingErrorMessages.forCode("KV_URI_INVALID"));
    }

    @Test
    void assigningADnsCredentialNamesBothCredentialsByReference() {
        CredentialReferenceEntity dns = credential("cred-new", "DNS", "AWS_ROUTE53", "Route 53");
        when(credentials.findByCredentialXrefAndOrganizationId("cred-new", ORG)).thenReturn(Optional.of(dns));
        DomainCredentialConfigEntity config = config();
        config.getDnsConfig().put("www.example.com", "cred-old");

        configService.patchDnsCredential(ORG, "example.com", "www.example.com", "cred-new");

        AuditEventRow row = onlyRow();
        assertThat(row.event()).isEqualTo("dns_credential.assigned");
        assertThat(row.summary()).isEqualTo("Assigned the Amazon Route 53 DNS credential 'Route 53' to www.example.com");
        assertThat(row.details().changes()).containsExactly(new AuditChange("credential", "cred-old", "cred-new"));
        assertThat(row.details().attributes()).containsExactly(Map.entry("certificateDomain", "example.com"));
    }

    @Test
    void aDeploymentTargetIsAddedOnceAndItsPlanIsKeptByNameOnly() throws Exception {
        CredentialReferenceEntity alb = credential("cred-alb", "DEPLOYMENT", "AWS_ACM", "Prod ACM");
        when(credentials.findByCredentialXrefAndOrganizationId("cred-alb", ORG)).thenReturn(Optional.of(alb));
        DomainCredentialConfigEntity config = config();
        AddDeploymentTargetRequest request = new AddDeploymentTargetRequest();
        request.setCredentialXref("cred-alb");
        request.setTargets(json.readTree("{\"certificateArn\":\"" + LISTENER_ARN + "\"}"));

        configService.addDeploymentTarget(ORG, "example.com", request);
        configService.addDeploymentTarget(ORG, "example.com", request);
        AddDeploymentTargetRequest noPlan = new AddDeploymentTargetRequest();
        noPlan.setCredentialXref("cred-alb");
        configService.addDeploymentTarget(ORG, "example.com", noPlan);
        configService.removeDeploymentTarget(ORG, "example.com", "cred-alb");
        configService.removeDeploymentTarget(ORG, "example.com", "cred-alb");

        List<AuditEventRow> rows = rows();
        assertThat(rows).extracting(AuditEventRow::event).as("a repeat add with a plan replaces it; without one,"
                        + " and a second removal, change nothing")
                .containsExactly("deployment_target.added", "deployment_target.updated", "deployment_target.removed");
        assertThat(rows).extracting(AuditEventRow::summary).containsExactly(
                "Added the AWS Certificate Manager deployment target 'Prod ACM' for example.com",
                "Changed the AWS Certificate Manager deployment target 'Prod ACM' for example.com",
                "Removed the AWS Certificate Manager deployment target 'Prod ACM' from example.com");
        assertThat(rows.get(0).details().attributes()).containsExactly(new java.util.AbstractMap.SimpleEntry<>("targets", null));
        assertThat(rows).allSatisfy(row -> assertThat(rowText(row)).doesNotContain("123456789012"));
    }

    @Test
    void aProviderNoOneWroteWordsForIsKeptOnlyWhenItLooksLikeACode() {
        assertThat(CredentialAuditRecorder.providerName("cloudflare")).isEqualTo("Cloudflare");
        assertThat(CredentialAuditRecorder.providerName("NEW_DNS_CO")).isEqualTo("NEW_DNS_CO");
        assertThat(CredentialAuditRecorder.providerName("my provider; drop table")).isNull();
        assertThat(CredentialAuditRecorder.providerName(" ")).isNull();
    }

    private void assertNoSecret(AuditEventRow row) {
        assertThat(rowText(row)).doesNotContain(API_TOKEN).doesNotContain(CLIENT_SECRET)
                .doesNotContain("example-vault").doesNotContain("vault.azure.net");
        assertThat(row.outcome()).isEqualTo(AuditOutcome.SUCCESS);
    }

    private String rowText(AuditEventRow row) {
        try {
            return row + json.writeValueAsString(row.details());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private AuditEventRow onlyRow() {
        List<AuditEventRow> rows = rows();
        assertThat(rows).hasSize(1);
        return rows.get(0);
    }

    private List<AuditEventRow> rows() {
        ArgumentCaptor<AuditEventRow> captor = ArgumentCaptor.forClass(AuditEventRow.class);
        verify(recorder, atLeastOnce()).record(captor.capture());
        return new ArrayList<>(captor.getAllValues());
    }

    private DomainCredentialConfigEntity config() {
        UserDomainCertEntity domain = mock(UserDomainCertEntity.class);
        when(domain.getId()).thenReturn(77L);
        when(domains.findByOrganizationIdAndDomain(ORG, "example.com")).thenReturn(Optional.of(domain));
        DomainCredentialConfigEntity config = new DomainCredentialConfigEntity();
        config.setId(5L);
        config.setUserDomainCertId(77L);
        config.setDnsConfig(new LinkedHashMap<>());
        config.setDeploymentTargets(new ArrayList<>());
        when(configs.findByUserDomainCertId(77L)).thenReturn(Optional.of(config));
        when(configs.save(eq(config))).thenReturn(config);
        return config;
    }

    private static CredentialReferenceEntity credential(String xref, String type, String provider, String name) {
        return CredentialReferenceEntity.builder().id(9L).credentialXref(xref).organizationId(ORG).type(type)
                .provider(provider).description(name).status("ACTIVE").build();
    }

    private static Throwable catchThrown(ThrowingRunnable call) {
        try {
            call.run();
        } catch (Throwable thrown) {
            return thrown;
        }
        throw new AssertionError("expected a refusal");
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
