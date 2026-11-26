// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.enums.KeyCustody;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStore;
import com.certmanagement.support.integrations.secret.agent.AgentSecretStoreProperties;
import com.certmanagement.support.integrations.secret.agent.gcp.GcpSecretManagerAgentDriver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.mock.env.MockEnvironment;

import java.lang.reflect.Field;
import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import static com.certmanagement.service.cert.export.CertExportUnavailableReason.EXPIRED;
import static com.certmanagement.service.cert.export.CertExportUnavailableReason.FEATURE_DISABLED;
import static com.certmanagement.service.cert.export.CertExportUnavailableReason.NOT_ACTIVE;
import static com.certmanagement.service.cert.export.CertExportUnavailableReason.NOT_PLATFORM_STORED;
import static com.certmanagement.service.cert.export.CertExportUnavailableReason.NO_MATERIAL;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertExportEligibilityPolicyTest {

    static final String XREF = "cert-123";
    static final String HANDLE = "https://kv-agent.vault.azure.net/secrets/cert-123";
    private static final Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    private final AgentSecretStore store = mock(AgentSecretStore.class);
    private CertExportEligibilityPolicy policy;

    @BeforeEach
    void setUp() {
        when(store.isReady()).thenReturn(true);
        when(store.isAgentCertificateHandle(HANDLE, XREF)).thenReturn(true);
        policy = policyWith(store);
    }

    /** A cert the agent stored, valid for another month. */
    static CertificateEntity exportableCert() {
        return CertificateEntity.builder()
                .id(9L)
                .certificateXref(XREF)
                .caProvider(CaProvider.LETS_ENCRYPT)
                .status("ACTIVE")
                .certSecretHandle(HANDLE)
                .fingerprintSha256("AB:CD")
                .validTo(OffsetDateTime.ofInstant(NOW, ZoneOffset.UTC).plusDays(30))
                .build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"ACTIVE", "RENEWING"})
    void liveLetsEncryptCertInOurStore_isExportableInEveryFormat(String status) {
        CertificateEntity cert = exportableCert();
        cert.setStatus(status);

        CertExportEligibility eligibility = policy.evaluate(cert);

        assertThat(eligibility.available()).isTrue();
        assertThat(eligibility.reason()).isNull();
        assertThat(eligibility.formats()).containsExactly(CertExportFormat.values());
    }

    @ParameterizedTest
    @EnumSource(value = CaProvider.class, names = {"DIGICERT", "GLOBALSIGN"})
    void everyCaThePlatformStores_isExportable(CaProvider ca) {
        CertificateEntity cert = exportableCert();
        cert.setCaProvider(ca);

        CertExportEligibility eligibility = policy.evaluate(cert);

        assertThat(eligibility.available()).isTrue();
        assertThat(eligibility.formats()).containsExactly(CertExportFormat.values());
    }

    @Test
    void customerHeldKey_offersTheCertificateAndChainOnly() {
        CertificateEntity cert = exportableCert();
        cert.setKeyCustody(KeyCustody.CUSTOMER_HELD);

        CertExportEligibility eligibility = policy.evaluate(cert);

        assertThat(eligibility.available()).isTrue();
        assertThat(eligibility.formats()).containsExactly(CertExportFormat.FULLCHAIN_PEM, CertExportFormat.CERTIFICATE_PEM,
                CertExportFormat.CERTIFICATE_DER, CertExportFormat.PKCS7);
    }

    @Test
    void akamaiCps_isACustomerHeldKey() {
        CertificateEntity cert = exportableCert();
        cert.setSpecialCertificateType("AKAMAI_CPS");
        cert.setKeyCustody(KeyCustody.CUSTOMER_HELD);

        assertThat(policy.evaluate(cert).formats()).noneMatch(CertExportFormat::includesPrivateKey);
    }

    @Test
    void expiredStatusOrPastValidTo_isExpired() {
        CertificateEntity byStatus = exportableCert();
        byStatus.setStatus("EXPIRED");
        assertReason(byStatus, EXPIRED);

        CertificateEntity byDate = exportableCert();
        byDate.setValidTo(OffsetDateTime.ofInstant(NOW, ZoneOffset.UTC));
        assertReason(byDate, EXPIRED);
    }

    @ParameterizedTest
    @ValueSource(strings = {"PENDING", "FAILED", "REVOKED", "RENEW_SUCCESS", "RENEWAL_FAILED", "DELETED"})
    void nonLiveStatuses_areNotActive(String status) {
        CertificateEntity cert = exportableCert();
        cert.setStatus(status);
        assertReason(cert, NOT_ACTIVE);
    }

    @Test
    void missingHandleOrFingerprint_isNoMaterial() {
        CertificateEntity noHandle = exportableCert();
        noHandle.setCertSecretHandle(" ");
        assertReason(noHandle, NO_MATERIAL);

        CertificateEntity noFingerprint = exportableCert();
        noFingerprint.setFingerprintSha256(null);
        assertReason(noFingerprint, NO_MATERIAL);
    }

    @Test
    void handleNamingAnotherSecret_isNotPlatformStored() {
        CertificateEntity cert = exportableCert();
        cert.setCertSecretHandle("https://kv-agent.vault.azure.net/secrets/certping-org7-cred-1");
        assertReason(cert, NOT_PLATFORM_STORED);
    }

    @Test
    void unconfiguredOrMissingStore_isNotPlatformStored() {
        when(store.isReady()).thenReturn(false);
        assertReason(exportableCert(), NOT_PLATFORM_STORED);

        policy = policyWith(null);
        assertReason(exportableCert(), NOT_PLATFORM_STORED);
    }

    @Test
    void gcpHandles_onlyTheVersionedFormTheAgentPersistsIsPlatformStored() throws Exception {
        policy = policyWith(gcpDriver("123456789012"));
        CertificateEntity cert = exportableCert();

        cert.setCertSecretHandle("projects/123456789012/secrets/certping-cert-123/versions/3");
        assertThat(policy.evaluate(cert).available()).isTrue();

        cert.setCertSecretHandle("projects/123456789012/secrets/certping-cert-123");
        assertReason(cert, NOT_PLATFORM_STORED);
        cert.setCertSecretHandle("projects/example-project/secrets/certping-cert-123");
        assertReason(cert, NOT_PLATFORM_STORED);
    }

    @Test
    void featureDisabled_comesFirstAndOffersNothing() {
        assertReason(exportableCert(), false, FEATURE_DISABLED);
        assertThat(policy.evaluate(exportableCert(), true).available()).isTrue();
    }

    /** A real GCP driver, its client never built: the eligibility checks are pure string checks. */
    private static GcpSecretManagerAgentDriver gcpDriver(String projectNumber) throws Exception {
        GcpSecretManagerAgentDriver driver = new GcpSecretManagerAgentDriver(
                new AgentSecretStoreProperties(), new MockEnvironment());
        setField(driver, "projectId", "example-project");
        setField(driver, "projectNumber", projectNumber);
        setField(driver, "ownSecretPrefix", "certping-");
        return driver;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private void assertReason(CertificateEntity cert, boolean downloadEnabled, CertExportUnavailableReason expected) {
        CertExportEligibility eligibility = policy.evaluate(cert, downloadEnabled);
        assertThat(eligibility).isEqualTo(CertExportEligibility.unavailable(expected));
    }

    private void assertReason(CertificateEntity cert, CertExportUnavailableReason expected) {
        CertExportEligibility eligibility = policy.evaluate(cert);
        assertThat(eligibility.available()).isFalse();
        assertThat(eligibility.reason()).isEqualTo(expected);
        assertThat(eligibility.formats()).isEmpty();
    }

    private CertExportEligibilityPolicy policyWith(AgentSecretStore secretStore) {
        StaticListableBeanFactory beans = new StaticListableBeanFactory();
        if (secretStore != null) {
            beans.addBean("agentSecretStore", secretStore);
        }
        return new CertExportEligibilityPolicy(beans.getBeanProvider(AgentSecretStore.class),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }
}
