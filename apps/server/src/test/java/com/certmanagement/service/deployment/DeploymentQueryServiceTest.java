// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment;

import com.certmanagement.dto.deployment.DeploymentQueryRequest;
import com.certmanagement.entity.CertDeploymentConfigEntity;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.entity.DeploymentEntity;
import com.certmanagement.entity.UserDomainCertEntity;
import com.certmanagement.exception.BadRequestException;
import com.certmanagement.repository.CertDeploymentConfigRepository;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.repository.DeploymentRepository;
import com.certmanagement.service.cert.CredentialReferenceService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentQueryServiceTest {

    @Mock
    private DeploymentRepository deploymentRepository;

        @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CertDeploymentConfigRepository certDeploymentConfigRepository;

    @Mock
    private CredentialReferenceService credentialReferenceService;


    @InjectMocks
    private DeploymentQueryService deploymentQueryService;
    private long idCounter = 100;

    private static final Long ORGANIZATION_ID = 1L;
    private static final Long UDC_ID_1 = 11L;
    private static final Long UDC_ID_2 = 12L;

    @Test
    void query_withNoOptionalFilters_usesListModeAndPassesNulls() {
        DeploymentQueryRequest filter = new DeploymentQueryRequest();
        PageRequest pageable = PageRequest.of(0, 25);
        DeploymentEntity deployment = DeploymentEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .certificateXref("cert-1")
                .requestId("req-1")
                .build();
        Page<DeploymentEntity> page = new PageImpl<>(List.of(deployment));

        CertificateEntity cert = CertificateEntity.builder()
                .certificateXref("cert-1")
                .wildcard(false)
                .san(true)
                .sanDomains(new String[]{"www.example.com"})
                .validFrom(OffsetDateTime.parse("2026-04-01T00:00:00Z"))
                .validTo(OffsetDateTime.parse("2026-07-01T00:00:00Z"))
                .issuer("Let's Encrypt")
                .serialNumber("01AB")
                .fingerprintSha256("fp")
                .userDomainCert(UserDomainCertEntity.builder().domain("example.com").organizationId(ORGANIZATION_ID).build())
                .build();

        when(deploymentRepository.search(eq(ORGANIZATION_ID), eq(null), eq(null), eq(null), eq(null), eq(false), eq(null), eq(null), eq(null), eq(pageable)))
                .thenReturn(page);
        when(certificateRepository.findByOrganizationIdAndCertificateXrefIn(eq(ORGANIZATION_ID), eq(List.of("cert-1"))))
                .thenReturn(List.of(cert));

        Object result = deploymentQueryService.query(ORGANIZATION_ID, filter, pageable);

        @SuppressWarnings("unchecked")
        Map<String, Object> response = (Map<String, Object>) result;
        assertThat(response).isInstanceOf(Map.class);
        assertThat(response.get("mode")).isEqualTo("list");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
        assertThat(items).hasSize(1);
        assertThat(items.get(0).get("certificateXref")).isEqualTo("cert-1");
        assertThat(items.get(0).get("domain")).isEqualTo("example.com");
        assertThat(items.get(0).get("wildcard")).isEqualTo(false);
        assertThat(items.get(0).get("san")).isEqualTo(true);
        assertThat(items.get(0).get("sanDomains")).isEqualTo(List.of("www.example.com"));
        verify(deploymentRepository).search(eq(ORGANIZATION_ID), eq(null), eq(null), eq(null), eq(null), eq(false), eq(null), eq(null), eq(null), eq(pageable));
    }

    @Test
    void query_singleDeployment_exposesVaultHandles() {
        Map<String, Object> item = querySingleDeploymentWithHandles();

        assertThat(item)
                .containsEntry("certSecretHandle", "https://customer-kv.vault.azure.net/secrets/cert-1")
                .containsEntry("deploymentCredHandle", "https://customer-kv.vault.azure.net/secrets/cred-1");
    }

    private Map<String, Object> querySingleDeploymentWithHandles() {
        DeploymentQueryRequest filter = new DeploymentQueryRequest();
        filter.setRequestId("req-1");
        DeploymentEntity deployment = DeploymentEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .certificateXref("cert-1")
                .requestId("req-1")
                .certSecretHandle("https://customer-kv.vault.azure.net/secrets/cert-1")
                .deploymentCredHandle("https://customer-kv.vault.azure.net/secrets/cred-1")
                .build();
        when(deploymentRepository.findActiveByRequestIdAndOrganizationId("req-1", ORGANIZATION_ID))
                .thenReturn(Optional.of(deployment));
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORGANIZATION_ID))
                .thenReturn(Optional.empty());

        @SuppressWarnings("unchecked")
        Map<String, Object> response =
                (Map<String, Object>) deploymentQueryService.query(ORGANIZATION_ID, filter, PageRequest.of(0, 25));
        assertThat(response.get("mode")).isEqualTo("single");
        @SuppressWarnings("unchecked")
        Map<String, Object> item = (Map<String, Object>) response.get("item");
        return item;
    }

    @Test
    void getCredentialConfig_returnsEntityDetails() {
        CertificateEntity cert = CertificateEntity.builder()
                .certificateXref("cert-123")
                .userDomainCertId(UDC_ID_1)
                .userDomainCert(UserDomainCertEntity.builder().domain("example.org").organizationId(ORGANIZATION_ID).build())
                .build();
        CertDeploymentConfigEntity entity = CertDeploymentConfigEntity.builder()
                .organizationId(ORGANIZATION_ID)
                .userDomainCertId(UDC_ID_1)
                .deploymentCredentialId(21L)
                .deploymentCredentialXref("cred-201")
                .provider("KUBERNETES_SECRETS")
                .configJson("{\"authProvider\":\"SA_INCLUSTER\"}")
                .build();

        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-123", ORGANIZATION_ID))
                .thenReturn(Optional.of(cert));
        when(credentialReferenceService.getByXref(ORGANIZATION_ID, "cred-201"))
                .thenReturn(CredentialReferenceEntity.builder()
                        .id(21L)
                        .credentialXref("cred-201")
                        .type("DEPLOYMENT")
                        .status("ACTIVE")
                        .build());
        when(certDeploymentConfigRepository.findActiveByCertAndCredentialXref(ORGANIZATION_ID, UDC_ID_1, "cred-201"))
                .thenReturn(Optional.of(entity));

        Map<String, Object> result = deploymentQueryService.getCredentialConfig(ORGANIZATION_ID, "cert-123", "cred-201");

        assertThat(result.get("certXref")).isEqualTo("cert-123");
        assertThat(result.get("domain")).isEqualTo("example.org");
        assertThat(result.get("deploymentCredentialXref")).isEqualTo("cred-201");
        assertThat(result.get("provider")).isEqualTo("KUBERNETES_SECRETS");
        assertThat(result.get("config")).isEqualTo("{\"authProvider\":\"SA_INCLUSTER\"}");
    }

    @Test
    void getCredentialConfig_blankInputs_throwBadRequest() {
        assertThatThrownBy(() -> deploymentQueryService.getCredentialConfig(ORGANIZATION_ID, " ", "cred-1"))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Both certXref and deploymentCredentialXref are required");
    }

    @Test
    void query_withPartialFilters_preservesProvidedValuesAndNormalizesBlankStrings() {
        DeploymentQueryRequest filter = new DeploymentQueryRequest();
        filter.setCertificateXref("  ");
        filter.setStatus("SUCCESS");
        filter.setFlowType("REQUEST");
        filter.setFrom(OffsetDateTime.parse("2026-04-01T00:00:00Z"));

        PageRequest pageable = PageRequest.of(0, 10);
        Page<DeploymentEntity> page = new PageImpl<>(List.of());

        when(deploymentRepository.search(eq(ORGANIZATION_ID), eq(null), eq("SUCCESS"), eq(null), eq("REQUEST"), eq(false), eq(null), eq(filter.getFrom()), eq(null), eq(pageable)))
                .thenReturn(page);

        deploymentQueryService.query(ORGANIZATION_ID, filter, pageable);

        ArgumentCaptor<String> certificateXrefCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> statusCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> targetTypeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> flowTypeCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<OffsetDateTime> fromCaptor = ArgumentCaptor.forClass(OffsetDateTime.class);
        ArgumentCaptor<OffsetDateTime> toCaptor = ArgumentCaptor.forClass(OffsetDateTime.class);

        verify(deploymentRepository).search(
                eq(ORGANIZATION_ID),
                certificateXrefCaptor.capture(),
                statusCaptor.capture(),
                targetTypeCaptor.capture(),
                flowTypeCaptor.capture(),
                eq(false),
                eq(null),
                fromCaptor.capture(),
                toCaptor.capture(),
                eq(pageable));

        assertThat(certificateXrefCaptor.getValue()).isNull();
        assertThat(statusCaptor.getValue()).isEqualTo("SUCCESS");
        assertThat(targetTypeCaptor.getValue()).isNull();
        assertThat(flowTypeCaptor.getValue()).isEqualTo("REQUEST");
        assertThat(fromCaptor.getValue()).isEqualTo(filter.getFrom());
        assertThat(toCaptor.getValue()).isNull();
    }

    @Test
    void query_withRequestId_usesSingleLookupAndIgnoresOtherFilters() {
        DeploymentQueryRequest filter = new DeploymentQueryRequest();
        filter.setRequestId("req-123");
        filter.setStatus("FAILED");
        filter.setView("summary");

        DeploymentEntity entity = DeploymentEntity.builder()
                .id(++idCounter)
                .organizationId(ORGANIZATION_ID)
                .requestId("req-123")
                .build();

        when(deploymentRepository.findActiveByRequestIdAndOrganizationId("req-123", ORGANIZATION_ID))
                .thenReturn(Optional.of(entity));
        when(certificateRepository.findByCertificateXrefAndOrganizationId("cert-1", ORGANIZATION_ID))
                .thenReturn(Optional.of(CertificateEntity.builder()
                        .certificateXref("cert-1")
                        .wildcard(true)
                        .san(false)
                        .sanDomains(new String[]{})
                        .userDomainCert(UserDomainCertEntity.builder().domain("one.example.com").organizationId(ORGANIZATION_ID).build())
                        .build()));

        entity.setCertificateXref("cert-1");

        Object result = deploymentQueryService.query(ORGANIZATION_ID, filter, PageRequest.of(0, 10));

        @SuppressWarnings("unchecked")
        Map<String, Object> response = (Map<String, Object>) result;
        assertThat(response).isInstanceOf(Map.class);
        assertThat(response.get("mode")).isEqualTo("single");
        @SuppressWarnings("unchecked")
        Map<String, Object> item = (Map<String, Object>) response.get("item");
        assertThat(item.get("domain")).isEqualTo("one.example.com");
        assertThat(item.get("wildcard")).isEqualTo(true);
        assertThat(item.get("san")).isEqualTo(false);
        verify(deploymentRepository).findActiveByRequestIdAndOrganizationId("req-123", ORGANIZATION_ID);
    }

        @Test
        void query_listMode_withUserDomainCertIdFilter_passesFilterFlagAndId() {
                Long userDomainCertId = 201L;
                DeploymentQueryRequest filter = new DeploymentQueryRequest();
                filter.setUserDomainCertId(userDomainCertId);
                PageRequest pageable = PageRequest.of(0, 20);

                when(deploymentRepository.search(
                                eq(ORGANIZATION_ID),
                                eq(null),
                                eq(null),
                                eq(null),
                                eq(null),
                                eq(true),
                                eq(userDomainCertId),
                                eq(null),
                                eq(null),
                                eq(pageable)
                )).thenReturn(new PageImpl<>(List.of()));

                deploymentQueryService.query(ORGANIZATION_ID, filter, pageable);

                verify(deploymentRepository).search(
                                eq(ORGANIZATION_ID),
                                eq(null),
                                eq(null),
                                eq(null),
                                eq(null),
                                eq(true),
                                eq(userDomainCertId),
                                eq(null),
                                eq(null),
                                eq(pageable)
                );
        }

        @Test
        void query_summaryMode_supportsNestedTupleShapeFromJpa() {
                DeploymentQueryRequest filter = new DeploymentQueryRequest();
                filter.setView("summary");

                when(deploymentRepository.summary(eq(ORGANIZATION_ID), eq(null), eq(null), eq(null), eq(null), eq(false), eq(null), eq(null), eq(null)))
                                .thenReturn(new Object[]{new Object[]{4L, 1L, 1L, 1L, 1L}});

                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) deploymentQueryService.query(ORGANIZATION_ID, filter, PageRequest.of(0, 10));

                assertThat(result.get("mode")).isEqualTo("summary");
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("total", 4L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("success", 1L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("failed", 1L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("publishFailed", 1L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("inProgress", 1L);
        }

        @Test
        void query_summaryMode_treatsNullAggregateValuesAsZero() {
                DeploymentQueryRequest filter = new DeploymentQueryRequest();
                filter.setView("summary");

                when(deploymentRepository.summary(eq(ORGANIZATION_ID), eq(null), eq(null), eq(null), eq(null), eq(false), eq(null), eq(null), eq(null)))
                                .thenReturn(new Object[]{0L, null, null, null, null});

                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) deploymentQueryService.query(ORGANIZATION_ID, filter, PageRequest.of(0, 10));

                assertThat(result.get("mode")).isEqualTo("summary");
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("total", 0L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("success", 0L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("failed", 0L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("publishFailed", 0L);
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("inProgress", 0L);
        }

        @Test
        void query_listMode_withAllFiltersProvided_passesEveryFilter() {
                OffsetDateTime from = OffsetDateTime.parse("2026-04-01T00:00:00Z");
                OffsetDateTime to = OffsetDateTime.parse("2026-04-10T00:00:00Z");

                DeploymentQueryRequest filter = new DeploymentQueryRequest();
                filter.setCertificateXref("cert-123");
                filter.setStatus("SUCCESS");
                filter.setTargetType("AWS_ACM");
                filter.setFlowType("MANUAL");
                filter.setFrom(from);
                filter.setTo(to);

                PageRequest pageable = PageRequest.of(0, 20);
                when(deploymentRepository.search(
                                eq(ORGANIZATION_ID),
                                eq("cert-123"),
                                eq("SUCCESS"),
                                eq("AWS_ACM"),
                                eq("MANUAL"),
                                eq(false),
                                eq(null),
                                eq(from),
                                eq(to),
                                eq(pageable)))
                                .thenReturn(new PageImpl<>(List.of()));

                deploymentQueryService.query(ORGANIZATION_ID, filter, pageable);

                verify(deploymentRepository).search(
                                eq(ORGANIZATION_ID),
                                eq("cert-123"),
                                eq("SUCCESS"),
                                eq("AWS_ACM"),
                                eq("MANUAL"),
                                eq(false),
                                eq(null),
                                eq(from),
                                eq(to),
                                eq(pageable));
        }

        @Test
        void query_summaryMode_withAllFiltersProvided_passesEveryFilter() {
                OffsetDateTime from = OffsetDateTime.parse("2026-04-01T00:00:00Z");
                OffsetDateTime to = OffsetDateTime.parse("2026-04-10T00:00:00Z");

                DeploymentQueryRequest filter = new DeploymentQueryRequest();
                filter.setView("summary");
                filter.setCertificateXref("cert-123");
                filter.setStatus("SUCCESS");
                filter.setTargetType("AWS_ACM");
                filter.setFlowType("MANUAL");
                filter.setFrom(from);
                filter.setTo(to);

                when(deploymentRepository.summary(
                                eq(ORGANIZATION_ID),
                                eq("cert-123"),
                                eq("SUCCESS"),
                                eq("AWS_ACM"),
                                eq("MANUAL"),
                                eq(false),
                                eq(null),
                                eq(from),
                                eq(to)))
                                .thenReturn(new Object[]{new Object[]{2L, 2L, 0L, 0L, 0L}});

                @SuppressWarnings("unchecked")
                Map<String, Object> result = (Map<String, Object>) deploymentQueryService.query(ORGANIZATION_ID, filter, PageRequest.of(0, 20));

                assertThat(result.get("mode")).isEqualTo("summary");
                assertThat(result.get("summary")).hasFieldOrPropertyWithValue("total", 2L);
                verify(deploymentRepository).summary(
                                eq(ORGANIZATION_ID),
                                eq("cert-123"),
                                eq("SUCCESS"),
                                eq("AWS_ACM"),
                                eq("MANUAL"),
                                eq(false),
                                eq(null),
                                eq(from),
                                eq(to));
        }

            @Test
            void listUserDomainCertDeploymentSummary_returnsPagedAggregates() {
                PageRequest pageable = PageRequest.of(0, 20);
                                when(deploymentRepository.summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq(null), eq(false), eq(null), eq(false), eq(pageable)))
                        .thenReturn(new PageImpl<>(List.of(
                                new Object[]{UDC_ID_1, "example.com", 5L, 3L, 2L},
                                new Object[]{UDC_ID_2, "foo.com", 0L, 0L, 0L}
                        ), pageable, 2));

                Map<String, Object> result = deploymentQueryService
                        .listUserDomainCertDeploymentSummary(ORGANIZATION_ID, null, null, false, pageable);

                assertThat(result.get("page")).isEqualTo(0);
                assertThat(result.get("size")).isEqualTo(20);
                @SuppressWarnings("unchecked")
                List<Object> items = (List<Object>) result.get("items");
                assertThat(items).hasSize(2);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("domain", "example.com");
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsRequested", 5L);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsSucceeded", 3L);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsFailed", 2L);
            }

            @Test
            void listUserDomainCertDeploymentSummary_normalizesBlankDomainFilterToNull() {
                PageRequest pageable = PageRequest.of(0, 20);
                                when(deploymentRepository.summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq(null), eq(false), eq(null), eq(false), eq(pageable)))
                        .thenReturn(new PageImpl<>(List.of()));

                deploymentQueryService.listUserDomainCertDeploymentSummary(ORGANIZATION_ID, "  ", null, false, pageable);

                                verify(deploymentRepository).summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq(null), eq(false), eq(null), eq(false), eq(pageable));
            }

            @Test
            void listUserDomainCertDeploymentSummary_withDomainFilter_forwardsDomain() {
                PageRequest pageable = PageRequest.of(0, 20);
                when(deploymentRepository.summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq("example"), eq(false), eq(null), eq(false), eq(pageable)))
                        .thenReturn(new PageImpl<>(List.<Object[]>of(
                                new Object[]{UDC_ID_1, "example.com", 3L, 2L, 1L}
                        ), pageable, 1));

                Map<String, Object> result = deploymentQueryService
                        .listUserDomainCertDeploymentSummary(ORGANIZATION_ID, "example", null, false, pageable);

                verify(deploymentRepository).summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq("example"), eq(false), eq(null), eq(false), eq(pageable));
                @SuppressWarnings("unchecked")
                List<Object> items = (List<Object>) result.get("items");
                assertThat(items).hasSize(1);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("domain", "example.com");
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsRequested", 3L);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsSucceeded", 2L);
                assertThat(items.get(0)).hasFieldOrPropertyWithValue("deploymentsFailed", 1L);
            }

                        @Test
                        void listUserDomainCertDeploymentSummary_withUserDomainCertId_enablesFilter() {
                                PageRequest pageable = PageRequest.of(0, 20);
                                Long userDomainCertId = 202L;
                                when(deploymentRepository.summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq(null), eq(true), eq(userDomainCertId), eq(false), eq(pageable)))
                                                .thenReturn(new PageImpl<>(List.of()));

                                deploymentQueryService.listUserDomainCertDeploymentSummary(ORGANIZATION_ID, null, userDomainCertId, false, pageable);

                                verify(deploymentRepository).summarizeByUserDomainCert(eq(ORGANIZATION_ID), eq(null), eq(true), eq(userDomainCertId), eq(false), eq(pageable));
                        }

}
