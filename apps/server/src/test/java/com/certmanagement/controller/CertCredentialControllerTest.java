// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.security.GatewayRequestContext;
import com.certmanagement.service.cert.CredentialReferenceService;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.OffsetDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertCredentialControllerTest {

    @Mock
    private CredentialReferenceService credentialService;

    @Spy
    private ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    @InjectMocks
    private CertCredentialController controller;

    private static final Long ORGANIZATION_ID = 1L;

    @AfterEach
    void tearDown() {
        GatewayRequestContext.clear();
    }

    @Test
    void registerDns_returnsKvPathInResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-1", "user@example.com");

        CertCredentialController.RegisterCredentialRequest request =
                new CertCredentialController.RegisterCredentialRequest();
        request.setProvider("AZURE_DNS");
        request.setDescription("Primary DNS credential");
        request.setSecretHandle("https://kv.vault.azure.net/secrets/dns-cred");

        CredentialReferenceEntity entity = buildCredential("cred-1", "DNS", request.getSecretHandle());
        when(credentialService.registerDns(
                ORGANIZATION_ID,
                request.getProvider(),
                request.getDescription(),
                request.getSecretHandle(),
                null, null)).thenReturn(entity);

        ResponseEntity<CertCredentialController.CredentialResponse> response = controller.registerDns(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCredentialXref()).isEqualTo("cred-1");
        assertThat(response.getBody().getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/dns-cred");
    }

    @Test
    void registerCa_returnsTheCaCredential() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-ca", "user@example.com");
        CertCredentialController.RegisterCaCredentialRequest request =
                new CertCredentialController.RegisterCaCredentialRequest();
        request.setProvider("DIGICERT");
        request.setDescription("CertCentral");
        request.setCredJson(objectMapper.createObjectNode().put("apiKey", "dc-key"));
        when(credentialService.registerCa(ORGANIZATION_ID, "DIGICERT", "CertCentral", null, request.getCredJson()))
                .thenReturn(buildCredential("cred-ca", "CA", "https://kv.vault.azure.net/secrets/ca"));

        ResponseEntity<CertCredentialController.CredentialResponse> response = controller.registerCa(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody().getCredentialXref()).isEqualTo("cred-ca");
        assertThat(response.getBody().getType()).isEqualTo("CA");
    }

        @Test
        void registerDeployment_returnsKvPathInResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-1b", "user@example.com");

        CertCredentialController.RegisterDeploymentCredentialRequest request =
            new CertCredentialController.RegisterDeploymentCredentialRequest();
        request.setProvider("AZURE_KV");
        request.setDescription("Primary deployment credential");
        request.setSecretHandle("https://kv.vault.azure.net/secrets/deploy-cred");

        CredentialReferenceEntity entity = buildCredential("cred-deploy-1", "DEPLOYMENT", request.getSecretHandle());
        when(credentialService.registerDeployment(
            ORGANIZATION_ID,
            request.getProvider(),
            request.getDescription(),
            request.getSecretHandle(),
            null,
            null)).thenReturn(entity);

        ResponseEntity<CertCredentialController.CredentialResponse> response = controller.registerDeployment(request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCredentialXref()).isEqualTo("cred-deploy-1");
        assertThat(response.getBody().getType()).isEqualTo("DEPLOYMENT");
        assertThat(response.getBody().getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/deploy-cred");

        verify(credentialService).registerDeployment(
            ORGANIZATION_ID,
            request.getProvider(),
            request.getDescription(),
            request.getSecretHandle(),
            null,
            null);
        }


    @Test
    void getCredential_returnsKvPathInResponse() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-2", "user@example.com");

        CredentialReferenceEntity entity = buildCredential(
                "cred-2",
                "DEPLOYMENT",
                "https://kv.vault.azure.net/secrets/deploy-cred");
        when(credentialService.getByXref(ORGANIZATION_ID, "cred-2")).thenReturn(entity);

        ResponseEntity<CertCredentialController.CredentialResponse> response = controller.getCredential("cred-2");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getCredentialXref()).isEqualTo("cred-2");
        assertThat(response.getBody().getType()).isEqualTo("DEPLOYMENT");
        assertThat(response.getBody().getSecretHandle()).isEqualTo("https://kv.vault.azure.net/secrets/deploy-cred");
        assertThat(response.getBody().getConfigJson()).isEqualTo("{\"authProvider\":\"SA_INCLUSTER\"}");
    }

    @Test
    void listCredentials_returnsKvPathInItems() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-3", "user@example.com");

        CredentialReferenceEntity entity = buildCredential(
                "cred-3",
                "DNS",
                "https://kv.vault.azure.net/secrets/dns-cred-3");
        when(credentialService.list(ORGANIZATION_ID, "DNS")).thenReturn(List.of(entity));

        ResponseEntity<CertCredentialController.ListResponse> response = controller.listCredentials("DNS");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getTotalItems()).isEqualTo(1);
        assertThat(response.getBody().getItems()).hasSize(1);
        assertThat(response.getBody().getItems().get(0).getCredentialXref()).isEqualTo("cred-3");
        assertThat(response.getBody().getItems().get(0).getSecretHandle())
                .isEqualTo("https://kv.vault.azure.net/secrets/dns-cred-3");

        verify(credentialService).list(ORGANIZATION_ID, "DNS");
    }

    @Test
    void listCredentials_withoutType_returnsItemsAndKvPath() {
    GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-4", "user@example.com");

    CredentialReferenceEntity dnsEntity = buildCredential(
        "cred-4",
        "DNS",
        "https://kv.vault.azure.net/secrets/dns-cred-4");
    CredentialReferenceEntity deployEntity = buildCredential(
        "cred-5",
        "DEPLOYMENT",
        "https://kv.vault.azure.net/secrets/deploy-cred-5");
    when(credentialService.list(ORGANIZATION_ID, null)).thenReturn(List.of(dnsEntity, deployEntity));

    ResponseEntity<CertCredentialController.ListResponse> response = controller.listCredentials(null);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(response.getBody()).isNotNull();
    assertThat(response.getBody().getTotalItems()).isEqualTo(2);
    assertThat(response.getBody().getItems()).hasSize(2);
    assertThat(response.getBody().getItems().get(0).getSecretHandle())
        .isEqualTo("https://kv.vault.azure.net/secrets/dns-cred-4");
    assertThat(response.getBody().getItems().get(1).getSecretHandle())
        .isEqualTo("https://kv.vault.azure.net/secrets/deploy-cred-5");
    assertThat(response.getBody().getItems().get(1).getConfigJson())
        .isEqualTo("{\"authProvider\":\"SA_INCLUSTER\"}");

    verify(credentialService).list(ORGANIZATION_ID, null);
    }

    @Test
    void updateKvPath_forwardsConfigJsonToService() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-cred-6", "user@example.com");

        CertCredentialController.UpdateKvPathRequest request = new CertCredentialController.UpdateKvPathRequest();
        request.setSecretHandle("https://kv.vault.azure.net/secrets/deploy-cred-updated");
        String configJson = "{\"authMethod\":\"AWS\",\"clusterName\":\"prod\",\"namespaces\":\"all_namespaces\"}";
        try {
            request.setConfigJson(objectMapper.readTree(configJson));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        CredentialReferenceEntity entity = buildCredential(
                "cred-6",
                "DEPLOYMENT",
                "https://kv.vault.azure.net/secrets/deploy-cred-updated");
        when(credentialService.updateCredential(
                ORGANIZATION_ID,
                "cred-6",
                request.getSecretHandle(),
                configJson,
                null)).thenReturn(entity);

        ResponseEntity<java.util.Map<String, Object>> response = controller.updateKvPath("cred-6", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("credentialXref")).isEqualTo("cred-6");
        verify(credentialService).updateCredential(
                ORGANIZATION_ID,
                "cred-6",
                request.getSecretHandle(),
                configJson,
                null);
    }

    @Test
    void listCa_returnsMetadataOnly_neverTheHandleOrKey() throws Exception {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-ca-list", "user@example.com");
        CredentialReferenceEntity ca = buildCredential("cred-ca", "CA", "https://kv.vault.azure.net/secrets/dc-key");
        ca.setProvider("DIGICERT");
        ca.setConfigJson("{\"apiKey\":\"leak\"}");
        when(credentialService.listCa(ORGANIZATION_ID)).thenReturn(List.of(ca));

        ResponseEntity<CertCredentialController.CaCredentialListResponse> response = controller.listCa();

        assertThat(response.getBody().totalItems()).isEqualTo(1);
        assertThat(response.getBody().items().get(0).credentialXref()).isEqualTo("cred-ca");
        String json = objectMapper.writeValueAsString(response.getBody());
        assertThat(json).doesNotContain("secretHandle", "dc-key", "leak", "configJson", "apiKey");
    }

    @Test
    void replaceCaKey_returnsMetadataOnly() throws Exception {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-ca-put", "user@example.com");
        CertCredentialController.ReplaceCaKeyRequest request = new CertCredentialController.ReplaceCaKeyRequest();
        request.setCredJson(objectMapper.createObjectNode().put("apiKey", "new-key"));
        CredentialReferenceEntity ca = buildCredential("cred-ca", "CA", "https://kv.vault.azure.net/secrets/dc-key");
        when(credentialService.replaceCaKey(ORGANIZATION_ID, "cred-ca", null, request.getCredJson())).thenReturn(ca);

        ResponseEntity<CertCredentialController.CaCredentialResponse> response = controller.replaceCaKey("cred-ca", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(objectMapper.writeValueAsString(response.getBody())).doesNotContain("new-key", "dc-key");
    }

    @Test
    void deleteCa_inUse_isAConflict() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-ca-del", "user@example.com");
        when(credentialService.deleteCa(ORGANIZATION_ID, "cred-ca")).thenThrow(new com.certmanagement.exception
                .CredentialRejectedException(com.certmanagement.exception.CredentialRejectedException.IN_USE, "in use"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> controller.deleteCa("cred-ca"))
                .isInstanceOf(com.certmanagement.exception.ConflictException.class);
    }

    @Test
    void deleteCa_unused_isNoContent() {
        GatewayRequestContext.set(101, String.valueOf(ORGANIZATION_ID), "req-ca-del2", "user@example.com");
        when(credentialService.deleteCa(ORGANIZATION_ID, "cred-ca"))
                .thenReturn(buildCredential("cred-ca", "CA", null));

        assertThat(controller.deleteCa("cred-ca").getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void caEndpoints_withoutAnOrganizationInTheToken_areDenied_andNeverReachTheService() {
        // The organization comes only from the caller's token; there is no parameter to name another one.
        GatewayRequestContext.set(101, null, "req-ca-noorg", "user@example.com");
        CertCredentialController.ReplaceCaKeyRequest request = new CertCredentialController.ReplaceCaKeyRequest();
        request.setCredJson(objectMapper.createObjectNode().put("apiKey", "k"));

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> controller.listCa())
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> controller.replaceCaKey("cred-ca", request))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> controller.deleteCa("cred-ca"))
                .isInstanceOf(org.springframework.security.access.AccessDeniedException.class);
        org.mockito.Mockito.verifyNoInteractions(credentialService);
    }

    @Test
    void caEndpoints_passTheTokensOrganization_toTheService() {
        GatewayRequestContext.set(101, "7", "req-ca-org7", "user@example.com");
        when(credentialService.listCa(7L)).thenReturn(List.of());
        when(credentialService.deleteCa(7L, "cred-ca")).thenReturn(buildCredential("cred-ca", "CA", null));

        controller.listCa();
        controller.deleteCa("cred-ca");

        verify(credentialService).listCa(7L);
        verify(credentialService).deleteCa(7L, "cred-ca");
        org.mockito.Mockito.verifyNoMoreInteractions(credentialService);
    }

    private CredentialReferenceEntity buildCredential(String xref, String type, String secretHandle) {
        OffsetDateTime now = OffsetDateTime.parse("2026-04-10T10:00:00Z");
        return CredentialReferenceEntity.builder()
                .id(1L)
                .credentialXref(xref)
                .organizationId(ORGANIZATION_ID)
                .provider("AZURE_DNS")
                .type(type)
                .description("desc")
                .status("ACTIVE")
                .secretHandle(secretHandle)
                .configJson("DEPLOYMENT".equals(type) ? "{\"authProvider\":\"SA_INCLUSTER\"}" : null)
                .createdAt(now)
                .updatedAt(now)
                .build();
    }
}
