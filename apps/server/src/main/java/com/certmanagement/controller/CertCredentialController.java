// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.security.OrgResolver;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.service.cert.CredentialReferenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static com.certmanagement.security.Permissions.*;

/**
 * Credential reference API — stores KV path pointers only; credential values are NEVER
 * sent to or stored by this service.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Cert Credentials", description = "Credential reference management (KV path pointers)")
public class CertCredentialController {

    private final CredentialReferenceService credentialService;
    private final ObjectMapper objectMapper;

    @PostMapping(Paths.CERT_CREDS_DNS)
    @AuditFailure(value = AuditEventType.CREDENTIAL_CREATED, name = "#request.description")
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_CREATE + "')")
    @Operation(summary = "Register a DNS credential reference (KV path)",
            description = "423 while DNS_CREDENTIALS is off, for any provider but CERTPING.")
    public ResponseEntity<CredentialResponse> registerDns(
            @Valid @RequestBody RegisterCredentialRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CredentialReferenceEntity entity = credentialService.registerDns(
                resolvedOrgId, request.getProvider(), request.getDescription(),
                request.getSecretHandle(), request.getCredJson(), request.getConfigJson());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(entity));
    }

    @PostMapping(Paths.CERT_CREDS_DEPLOYMENT)
    @AuditFailure(value = AuditEventType.CREDENTIAL_CREATED, name = "#request.description")
    @FeatureGated(FeatureFlags.CREDENTIALS_MANAGEMENT)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_CREATE + "')")
    @Operation(summary = "Register a deployment credential reference (KV path)")
    public ResponseEntity<CredentialResponse> registerDeployment(
            @Valid @RequestBody RegisterDeploymentCredentialRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CredentialReferenceEntity entity = credentialService.registerDeployment(
                resolvedOrgId, request.getProvider(), request.getDescription(),
                request.getSecretHandle(), toJsonString(request.getConfigJson()), request.getCredJson());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(entity));
    }

    @PostMapping(Paths.CERT_CREDS_DISCOVERY)
    @AuditFailure(value = AuditEventType.CREDENTIAL_CREATED, name = "#request.description")
    @FeatureGated(FeatureFlags.CREDENTIALS_MANAGEMENT)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_CREATE + "')")
    @Operation(summary = "Register a read-only discovery credential (for example an AWS Organization)",
            description = "Discovery credentials can only scan. They are never used to push certificates.")
    public ResponseEntity<CredentialResponse> registerDiscovery(
            @Valid @RequestBody RegisterDeploymentCredentialRequest request) {
        CredentialReferenceEntity entity = credentialService.registerDiscovery(
                OrgResolver.fromJwt(), request.getProvider(), request.getDescription(),
                request.getSecretHandle(), toJsonString(request.getConfigJson()), request.getCredJson());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(entity));
    }

    @PostMapping(Paths.CERT_CREDS_CA)
    @AuditFailure(value = AuditEventType.CREDENTIAL_CREATED, name = "#request.description")
    @FeatureGated(FeatureFlags.CREDENTIALS_MANAGEMENT)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_CREATE + "')")
    @Operation(summary = "Register a certificate authority credential (your DigiCert API key)",
            description = "credJson {\"apiKey\"} is stored for the agent; or secretHandle points at your own Key Vault secret.")
    public ResponseEntity<CredentialResponse> registerCa(
            @Valid @RequestBody RegisterCaCredentialRequest request) {
        CredentialReferenceEntity entity = credentialService.registerCa(
                OrgResolver.fromJwt(), request.getProvider(), request.getDescription(),
                request.getSecretHandle(), request.getCredJson());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(entity));
    }

    @GetMapping(Paths.CERT_CREDS_CA)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_READ + "')")
    @Operation(summary = "List the organization's certificate authority credentials (metadata only, never the key)")
    public ResponseEntity<CaCredentialListResponse> listCa() {
        List<CaCredentialResponse> items = credentialService.listCa(OrgResolver.fromJwt())
                .stream().map(CertCredentialController::toCaResponse).toList();
        return ResponseEntity.ok(new CaCredentialListResponse(items, items.size()));
    }

    @PutMapping(Paths.CERT_CREDS_CA_XREF)
    @AuditFailure(value = AuditEventType.CREDENTIAL_UPDATED, target = "#credXref")
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_ROTATE + "')")
    @Operation(summary = "Replace the key of a certificate authority credential",
            description = "Write-only: send credJson {\"apiKey\"} (or a secretHandle); the key is never returned.")
    public ResponseEntity<CaCredentialResponse> replaceCaKey(
            @PathVariable String credXref, @RequestBody ReplaceCaKeyRequest request) {
        CredentialReferenceEntity entity = credentialService.replaceCaKey(OrgResolver.fromJwt(), credXref,
                request == null ? null : request.getSecretHandle(),
                request == null ? null : request.getCredJson());
        return ResponseEntity.ok(toCaResponse(entity));
    }

    @DeleteMapping(Paths.CERT_CREDS_CA_XREF)
    @AuditFailure(value = AuditEventType.CREDENTIAL_DELETED, target = "#credXref")
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_DELETE + "')")
    @Operation(summary = "Delete a certificate authority credential",
            description = "409 while a live certificate was issued with it.")
    public ResponseEntity<Void> deleteCa(@PathVariable String credXref) {
        try {
            credentialService.deleteCa(OrgResolver.fromJwt(), credXref);
        } catch (com.certmanagement.exception.CredentialRejectedException e) {
            if (com.certmanagement.exception.CredentialRejectedException.IN_USE.equals(e.getCode())) {
                throw new com.certmanagement.exception.ConflictException(e.getMessage());
            }
            throw e;
        }
        return ResponseEntity.noContent().build();
    }

    @GetMapping(Paths.CERT_CREDS_XREF)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_READ + "')")
    @Operation(summary = "Get credential reference info")
    public ResponseEntity<CredentialResponse> getCredential(
            @PathVariable String credXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CredentialReferenceEntity entity = credentialService.getByXref(resolvedOrgId, credXref);
        return ResponseEntity.ok(toResponse(entity));
    }

    @GetMapping(Paths.CERT_CREDS_BASE)
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_READ + "')")
    @Operation(summary = "List credential references for organization (optionally filtered by type)")
    public ResponseEntity<ListResponse> listCredentials(
            @RequestParam(required = false) String type) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        List<CredentialResponse> items = credentialService.list(resolvedOrgId, type)
                .stream().map(this::toResponse).toList();
        return ResponseEntity.ok(new ListResponse(items, items.size()));
    }

    @DeleteMapping(Paths.CERT_CREDS_XREF)
    @AuditFailure(value = AuditEventType.CREDENTIAL_DELETED, target = "#credXref")
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_DELETE + "')")
    @Operation(summary = "Soft-delete a credential reference",
            description = "423 while DNS_CREDENTIALS (a third-party DNS credential) or CREDENTIALS_MANAGEMENT (any credential but DNS) is off.")
    public ResponseEntity<Map<String, Object>> deleteCredential(
            @PathVariable String credXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CredentialReferenceEntity entity = credentialService.delete(resolvedOrgId, credXref);
        return ResponseEntity.ok(Map.of(
                "credentialXref", entity.getCredentialXref(),
                "status",         "DELETED",
                "deletedAt",      OffsetDateTime.now(ZoneOffset.UTC).toString(),
                "message",        "Credential reference deleted. Remember to remove the secret from your Azure KV."
        ));
    }

    @PutMapping(Paths.CERT_CREDS_XREF)
    @AuditFailure(value = AuditEventType.CREDENTIAL_UPDATED, target = "#credXref")
    @PreAuthorize("hasPermission(null, '" + CREDENTIAL_ROTATE + "')")
    @Operation(summary = "Update the KV path URI and optional deployment config for a credential reference",
            description = "423 while DNS_CREDENTIALS (a third-party DNS credential) or CREDENTIALS_MANAGEMENT (any credential but DNS) is off.")
    public ResponseEntity<Map<String, Object>> updateKvPath(
            @PathVariable String credXref,
            @Valid @RequestBody UpdateKvPathRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CredentialReferenceEntity entity = credentialService.updateCredential(
                resolvedOrgId, credXref, request.getSecretHandle(),
                toJsonString(request.getConfigJson()), request.getCredJson());
        String message;
        if (request.getCredJson() != null && !request.getCredJson().isNull() && !request.getCredJson().isMissingNode()) {
            message = "Credential secret rotated. New secret will be used on next cert issuance/renewal.";
        } else if (request.getSecretHandle() != null && !request.getSecretHandle().isBlank()) {
            message = "KV path updated. New path will be used on next cert issuance/renewal.";
        } else {
            message = "Credential scope updated. Configuration changes take effect immediately.";
        }
        return ResponseEntity.ok(Map.of(
                "credentialXref", entity.getCredentialXref(),
                "provider",       entity.getProvider(),
                "type",           entity.getType(),
                "status",         entity.getStatus(),
                "updatedAt",      entity.getUpdatedAt().toString(),
                "message",        message
        ));
    }

    @Data
    public static class RegisterCredentialRequest {
        @NotBlank private String provider;
        private String description;
        private String secretHandle;
        /**
         * Optional raw credential payload. Mutually exclusive with {@link #secretHandle},
         * except NAMECHEAP, where this may carry non-secret account metadata while
         * {@code secretHandle} points to the API-key secret; without a secretHandle, NAMECHEAP
         * follows the normal credJson-only flow.
         */
        private JsonNode credJson;
        /**
         * Non-secret details, for CERTPING only: the key's {@code tokenId}, {@code tokenPrefix} and
         * {@code expiresAt}, so its expiry is warned about and renewals are held once it has passed.
         */
        private JsonNode configJson;
    }

    @Data
    public static class RegisterDeploymentCredentialRequest {
        @NotBlank private String provider;
        private String description;
        private String secretHandle;
        private JsonNode configJson;
        private JsonNode credJson;
    }

    @Data
    public static class RegisterCaCredentialRequest {
        @NotBlank private String provider;
        private String description;
        private String secretHandle;
        private JsonNode credJson;
    }

    @Data
    public static class ReplaceCaKeyRequest {
        private String secretHandle;
        private JsonNode credJson;
    }

    /** A CA credential as the API shows it: no key, no secret handle. */
    public record CaCredentialResponse(String credentialXref, String provider, String description, String status,
                                       String createdAt, String updatedAt) {
    }

    public record CaCredentialListResponse(List<CaCredentialResponse> items, int totalItems) {
    }

    static CaCredentialResponse toCaResponse(CredentialReferenceEntity entity) {
        return new CaCredentialResponse(entity.getCredentialXref(), entity.getProvider(), entity.getDescription(),
                entity.getStatus(),
                entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : null,
                entity.getUpdatedAt() != null ? entity.getUpdatedAt().toString() : null);
    }

    @Data
    public static class UpdateKvPathRequest {
        private String secretHandle;
        private JsonNode configJson;
        /** When present, overwrites the secret at the existing KV path in place (rotate). */
        private JsonNode credJson;
    }

    @Data
    public static class CredentialResponse {
        private String credentialXref;
        private String provider;
        private String type;
        private String description;
        private String status;
        /** Set when a deployment target refused this credential (401/403); cleared by an update or a later success. */
        private String lastError;
        private String secretHandle;
        private String configJson;
        private String createdAt;
        private String updatedAt;
    }

    @Data
    @lombok.AllArgsConstructor
    public static class ListResponse {
        private List<CredentialResponse> items;
        private int totalItems;
    }

    private String toJsonString(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) return null;
        try {
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            throw new com.certmanagement.exception.BadRequestException("configJson is not valid JSON", e);
        }
    }

    private CredentialResponse toResponse(CredentialReferenceEntity entity) {
        CredentialResponse r = new CredentialResponse();
        r.setCredentialXref(entity.getCredentialXref());
        r.setProvider(entity.getProvider());
        r.setType(entity.getType());
        r.setDescription(entity.getDescription());
        r.setStatus(entity.getStatus());
        r.setLastError(entity.getLastErrorMessage());
        r.setSecretHandle(entity.getSecretHandle());
        r.setConfigJson(entity.getConfigJson());
        r.setCreatedAt(entity.getCreatedAt() != null ? entity.getCreatedAt().toString() : null);
        r.setUpdatedAt(entity.getUpdatedAt() != null ? entity.getUpdatedAt().toString() : null);
        return r;
    }

}
