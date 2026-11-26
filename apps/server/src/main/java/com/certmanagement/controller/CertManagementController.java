// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.controller;

import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditFailure;
import com.certmanagement.security.CallerPermissions;
import com.certmanagement.security.OrgResolver;

import com.certmanagement.annotation.FeatureGated;
import com.certmanagement.constants.ErrorCodes;
import com.certmanagement.constants.ExpiringCertsConstants;
import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.Paths;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.service.cert.DnsCredentialAvailability;
import com.certmanagement.service.FeatureFlagService;
import com.certmanagement.dto.cert.CertDeployRequest;
import com.certmanagement.dto.cert.CertIssuanceRequest;
import com.certmanagement.dto.cert.CertRenewalRequest;
import com.certmanagement.dto.cert.ConvertToAutomatedRequest;
import com.certmanagement.dto.cert.IssueManualRequest;
import com.certmanagement.dto.cert.RevokeRequest;
import com.certmanagement.dto.cert.TxtRecordDto;
import com.certmanagement.entity.CertificateEntity;
import com.certmanagement.service.cert.CertConversionService;
import com.certmanagement.repository.CertificateRepository;
import com.certmanagement.service.cert.CertIssuanceService;
import com.certmanagement.service.cert.CertManualIssuanceService;
import com.certmanagement.service.cert.export.CertExportEligibility;
import com.certmanagement.service.cert.export.CertExportEligibilityPolicy;
import com.certmanagement.util.UserFacingErrorMessages;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.util.StringUtils;
import com.certmanagement.enums.EventSource;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Slice;
import org.springframework.data.web.PageableDefault;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.certmanagement.security.Permissions.*;

/**
 * Certificate lifecycle API — /api/v1/certs/*
 *
 * Issue, renew, deploy, get status, list.
 * All write operations are async — 202 Accepted with PENDING/RENEWING status.
 * certping-agent processes commands; responses arrive via CertResponseProcessor.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "Cert Management", description = "Certificate lifecycle management")
public class CertManagementController {

    private final CertConversionService     certConversionService;
    private final CertIssuanceService       certIssuanceService;
    private final CertManualIssuanceService certManualIssuanceService;
    private final FeatureFlagService        featureFlagService;
    private final CertExportEligibilityPolicy certExportEligibilityPolicy;
    private final DnsCredentialAvailability dnsCredentialAvailability;

    // ------------------------------------------------------------------ //
    //  Issue certificate
    // ------------------------------------------------------------------ //

    @PostMapping(Paths.CERTS_ISSUE)
    @FeatureGated(FeatureFlags.CERTIFICATE_ISSUANCE)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_ISSUE_REQUESTED, name = "#request.domain")
    @Operation(summary = "Issue a new certificate (async — returns 202 Accepted)")
    public ResponseEntity<Map<String, Object>> issue(
            @Valid @RequestBody CertIssuanceRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        assertDnsCredentialsAvailable(resolvedOrgId, request);

        CertificateEntity cert = certIssuanceService.issue(resolvedOrgId, request);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "certificateXref", cert.getCertificateXref(),
                "domain",          cert.getDomain(),
                "caProvider",      cert.getCaProvider(),
                "status",          cert.getStatus(),
                "submittedAt",     OffsetDateTime.now(ZoneOffset.UTC).toString()
        ));
    }

    /**
     * A new certificate request may not name a third-party DNS credential, for its primary domain or any SAN
     * entry, while DNS credentials are off for the organization; CertPing DNS stays usable. Refused before
     * anything is reserved or saved. Renewing or converting a certificate already linked to one stays allowed.
     */
    private void assertDnsCredentialsAvailable(Long organizationId, CertIssuanceRequest request) {
        List<String> xrefs = new ArrayList<>();
        if (StringUtils.hasText(request.getDnsCredentialXref())) {
            xrefs.add(request.getDnsCredentialXref());
        }
        if (request.getSanDomainEntries() != null) {
            request.getSanDomainEntries().stream()
                    .map(CertIssuanceRequest.SanDomainEntry::getDnsCredentialXref)
                    .filter(StringUtils::hasText)
                    .forEach(xrefs::add);
        }
        dnsCredentialAvailability.assertUsable(organizationId, xrefs);
    }

    // ------------------------------------------------------------------ //
    //  CA provider availability
    // ------------------------------------------------------------------ //

    @GetMapping(Paths.CERTS_CA_PROVIDERS)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(
            summary = "List available CA providers for the calling organization",
            description = "Returns every supported CA and whether it is currently enabled for this " +
                          "organization. Checks both the global flag (super-admin-level) and the " +
                          "org-level override. Use this before rendering the CA picker in the " +
                          "issuance form so disabled CAs can be shown as unavailable rather than " +
                          "failing after submission.")
    public ResponseEntity<Map<String, Object>> getCaProviders() {
        Long orgId = OrgResolver.fromJwt();

        List<Map<String, Object>> providers = java.util.Arrays.stream(CaProvider.values())
                .map(ca -> {
                    String featureKey = CertIssuanceService.toCaFeatureKey(ca);
                    boolean available = featureFlagService.isEnabled(featureKey, orgId);
                    Map<String, Object> entry = new java.util.HashMap<>();
                    entry.put("key",        ca.name());
                    entry.put("featureKey", featureKey);
                    entry.put("available",  available);
                    return entry;
                })
                .collect(java.util.stream.Collectors.toList());

        Map<String, Object> response = new java.util.HashMap<>();
        response.put("caProviders", providers);
        return ResponseEntity.ok(response);
    }

    // ------------------------------------------------------------------ //
    //  Renew certificate
    // ------------------------------------------------------------------ //

    @PostMapping(Paths.CERTS_RENEW)
    @FeatureGated(FeatureFlags.CERTIFICATE_RENEWAL)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_RENEW + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_RENEWAL_REQUESTED, target = "#certXref")
    @Operation(summary = "Renew an existing certificate (async — returns 202 Accepted)")
    public ResponseEntity<Map<String, Object>> renew(
            @PathVariable String certXref,
            @RequestBody(required = false) CertRenewalRequest body) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CertificateEntity cert = certIssuanceService.renew(resolvedOrgId, certXref, body);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "certificateXref", cert.getCertificateXref(),
                "domain",          cert.getDomain(),
                "status",          cert.getStatus(),
                "submittedAt",     OffsetDateTime.now(ZoneOffset.UTC).toString()
        ));
    }

    // ------------------------------------------------------------------ //
    //  Deploy certificate
    // ------------------------------------------------------------------ //

    @PostMapping(Paths.CERTS_DEPLOY)
    @FeatureGated(FeatureFlags.CERTIFICATE_DEPLOYMENT)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DEPLOY + "')")
    @AuditFailure(value = AuditEventType.DEPLOYMENT_REQUESTED, target = "#certXref")
    @Operation(summary = "Deploy a certificate to a target store (async — returns 202 Accepted)")
    public ResponseEntity<Map<String, Object>> deploy(
            @PathVariable String certXref,
            @Valid @RequestBody CertDeployRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CertificateEntity cert = certIssuanceService.deploy(resolvedOrgId, certXref, request);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "certificateXref", cert.getCertificateXref(),
                "domain",          cert.getDomain(),
                "status",          cert.getStatus(),
                "submittedAt",     OffsetDateTime.now(ZoneOffset.UTC).toString()
        ));
    }

    // ------------------------------------------------------------------ //
    //  Delete certificate (soft) — DEPRECATED
    // ------------------------------------------------------------------ //

    /**
     * @deprecated Per-cert delete only tombstones one cert iteration on the domain
     *     and leaves the parent UserDomainCert plus its credential / deployment
     *     configs alive — useful when the previous flow was "cancel one in-flight
     *     issuance", but rarely what callers actually want. Prefer
     *     {@code DELETE /api/v1/user-domain-certificates/{userDomainCertId}}
     *     ({@link #deleteUserDomainCert}) which cascades every cert iteration on the
     *     domain plus the per-domain config rows in one shot. EXPIRED and REVOKED
     *     certs are also auto-soft-deleted by {@code CertExpiryCleanupService} 24h
     *     after they enter that state, so explicit per-cert delete is no longer the
     *     normal lifecycle path. Will be removed in a future release.
     */
    @Deprecated
    @DeleteMapping(Paths.CERTS_GET)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DELETE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_DELETED, target = "#certXref")
    @Operation(summary = "[DEPRECATED] Soft-delete a single certificate iteration",
            description = "Deprecated — prefer DELETE /api/v1/user-domain-certificates/{userDomainCertId} which "
                    + "cascades every cert iteration for the domain. Per-cert delete leaves the parent "
                    + "user_domain_certificate plus its domain_credential_config / cert_deployment_config "
                    + "rows alive; that's almost never the desired semantic.",
            deprecated = true)
    public ResponseEntity<Void> delete(
            @PathVariable String certXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        certIssuanceService.delete(resolvedOrgId, certXref);
        return ResponseEntity.noContent().build();
    }

    // ------------------------------------------------------------------ //
    //  Delete managed domain — cascades to every cert iteration + per-domain configs
    // ------------------------------------------------------------------ //

    @DeleteMapping(Paths.USER_DOMAIN_CERTS_ID)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_DELETE + "')")
    // All or nothing (one transaction): a failure is the request's one row. The managed domain's id is not a
    // certificate's, so the row names no target.
    @AuditFailure(AuditEventType.CERTIFICATE_DELETED)
    @Operation(summary = "Soft-delete a managed domain and cascade to every cert + per-domain credential / deployment configs",
            description = "The middle layer between deleting a single cert and deleting the whole organization. "
                    + "Soft-deletes the user_domain_certificate row, every certificate iteration ever issued for it "
                    + "(with their renewal_schedule / deployments / events / allocation), and the "
                    + "per-domain domain_credential_config + cert_deployment_config rows that span those certs.")
    public ResponseEntity<Void> deleteUserDomainCert(
            @PathVariable Long userDomainCertId) {
        Long resolvedOrgId = OrgResolver.fromJwt();
        certIssuanceService.deleteUserDomainCert(resolvedOrgId, userDomainCertId);
        return ResponseEntity.noContent().build();
    }

    // ------------------------------------------------------------------ //
    //  Revoke certificate
    // ------------------------------------------------------------------ //

    @PostMapping(Paths.CERTS_REVOKE)
    @FeatureGated(FeatureFlags.CERTIFICATE_REVOCATION)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_REVOKE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_REVOKE_REQUESTED, target = "#certXref")
    @Operation(summary = "Revoke a certificate (async — returns 202 Accepted)")
    public ResponseEntity<Map<String, Object>> revoke(
            @PathVariable String certXref,
            @RequestBody(required = false) RevokeRequest body) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        RevokeRequest request = body != null ? body : new RevokeRequest();

        CertificateEntity cert = certIssuanceService.revoke(resolvedOrgId, certXref, request);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "certificateXref", cert.getCertificateXref(),
                "status",          cert.getStatus(),
                "revokeReason",    request.getReason() != null ? request.getReason() : ErrorCodes.DEFAULT_REVOCATION_REASON
        ));
    }

    // ------------------------------------------------------------------ //
    //  Dashboard statistics
    // ------------------------------------------------------------------ //

    @GetMapping(Paths.CERTS_DASHBOARD)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get aggregate certificate statistics for a organization")
    public ResponseEntity<Map<String, Object>> dashboard() {
        Long resolvedOrgId = OrgResolver.fromJwt();
        Map<String, Object> dashboard = new LinkedHashMap<>(certIssuanceService.dashboard(resolvedOrgId));

        Page<CertificateEntity> certPage = certIssuanceService.list(
            resolvedOrgId,
            null,
            null,
            PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "updatedAt")));
        Map<String, CertIssuanceService.CredentialRefs> refsByXref =
                certIssuanceService.resolveCredentialRefsForResponseBatch(certPage.getContent());
        boolean downloadEnabled = isCertificateDownloadEnabled(resolvedOrgId);
        List<Map<String, Object>> items = certPage.getContent().stream()
            .map(c -> toCertSummary(c, refsByXref.get(c.getCertificateXref()), downloadEnabled))
            .toList();
        dashboard.put("items", items);

        return ResponseEntity.ok(dashboard);
    }

    // ------------------------------------------------------------------ //
    //  Expiring certificates
    // ------------------------------------------------------------------ //

    /**
     * ACTIVE certs expiring within {@code withinDays} (UTC now → now+N). Projection only
     * (no secret handles). Null {@link Pageable} is defaulted in the service to
     * {@code PageRequest.of(ExpiringCertsConstants.DEFAULT_PAGE, ExpiringCertsConstants.DEFAULT_PAGE_SIZE)}.
     * Page size is capped at {@link ExpiringCertsConstants#MAX_PAGE_SIZE} ({@code @PageableDefault}
     * has no max attribute in Spring Data; Spring's resolver ceiling is otherwise 2000).
     */
    @GetMapping(Paths.CERTS_EXPIRING)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(
            summary = "List ACTIVE certificates expiring within a look-ahead window",
            description = "Returns a Slice (no total count) of rows without secret handles. "
                    + "withinDays defaults to 7 and must be 1..90. "
                    + "Pagination uses Spring Pageable (page/size, default page=0 size=20, max size=100); "
                    + "a null pageable is treated as page=0 size=20 in the service.")
    public ResponseEntity<Map<String, Object>> listExpiring(
            @RequestParam(
                    required = false,
                    defaultValue = ExpiringCertsConstants.DEFAULT_WITHIN_DAYS_PARAM)
                    int withinDays,
            @PageableDefault(
                    page = ExpiringCertsConstants.DEFAULT_PAGE,
                    size = ExpiringCertsConstants.DEFAULT_PAGE_SIZE)
                    Pageable pageable) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        if (pageable.getPageSize() > ExpiringCertsConstants.MAX_PAGE_SIZE) {
            pageable = PageRequest.of(
                    pageable.getPageNumber(),
                    ExpiringCertsConstants.MAX_PAGE_SIZE,
                    pageable.getSort());
        }

        Slice<CertificateRepository.ExpiringCertificateRow> slice =
                certIssuanceService.listExpiring(resolvedOrgId, withinDays, pageable);

        List<Map<String, Object>> items = slice.getContent().stream()
                .map(this::toExpiringRow)
                .toList();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("items", items);
        body.put("page", slice.getNumber());
        body.put("size", slice.getSize());
        body.put("hasNext", slice.hasNext());
        body.put("withinDays", withinDays);
        return ResponseEntity.ok(body);
    }

    // ------------------------------------------------------------------ //
    //  Get certificate status
    // ------------------------------------------------------------------ //

    @GetMapping(Paths.CERTS_GET)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get certificate status and metadata")
    public ResponseEntity<Map<String, Object>> getStatus(
            @PathVariable String certXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CertificateEntity cert = certIssuanceService.getStatus(resolvedOrgId, certXref);
        return ResponseEntity.ok(toCertResponse(cert, isCertificateDownloadEnabled(resolvedOrgId)));
    }

    // ------------------------------------------------------------------ //
    //  List certificates
    // ------------------------------------------------------------------ //

    @GetMapping(Paths.CERTS_BASE)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "List certificates for a organization (optionally filtered by status and/or domain substring)")
    public ResponseEntity<Map<String, Object>> list(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String domain,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        Page<CertificateEntity> certPage = certIssuanceService.list(resolvedOrgId, status, domain, page, size);
        Map<String, CertIssuanceService.CredentialRefs> refsByXref =
                certIssuanceService.resolveCredentialRefsForResponseBatch(certPage.getContent());
        boolean downloadEnabled = isCertificateDownloadEnabled(resolvedOrgId);
        List<Map<String, Object>> items = certPage.getContent().stream()
                .map(c -> toCertSummary(c, refsByXref.get(c.getCertificateXref()), downloadEnabled))
                .toList();

        return ResponseEntity.ok(Map.of(
                "items",      items,
                "page",       page,
                "size",       size,
                "totalItems", certPage.getTotalElements(),
                "totalPages", certPage.getTotalPages()
        ));
    }

    @GetMapping(Paths.CERTS_HISTORY)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "List certificate history for a user-domain certificate (organization-scoped)")
    public ResponseEntity<Map<String, Object>> history(
            @RequestParam("udc_id") Long userDomainCertId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        Page<CertificateEntity> certPage = certIssuanceService.history(resolvedOrgId, userDomainCertId, page, size);
        Map<String, CertIssuanceService.CredentialRefs> refsByXref =
                certIssuanceService.resolveCredentialRefsForResponseBatch(certPage.getContent());
        boolean downloadEnabled = isCertificateDownloadEnabled(resolvedOrgId);
        Map<String, String> triggers = renewalTriggers(resolvedOrgId, certPage.getContent());
        List<Map<String, Object>> items = certPage.getContent().stream()
                .map(c -> {
                    Map<String, Object> item = toCertSummary(c, refsByXref.get(c.getCertificateXref()), downloadEnabled);
                    item.put("renewalTrigger", triggers.get(c.getCertificateXref()));
                    return item;
                })
                .toList();

        return ResponseEntity.ok(Map.of(
                "items",      items,
                "page",       page,
                "size",       size,
                "totalItems", certPage.getTotalElements(),
                "totalPages", certPage.getTotalPages()
        ));
    }

    private com.certmanagement.repository.CertificateEventRepository certificateEvents;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setCertificateEvents(com.certmanagement.repository.CertificateEventRepository certificateEvents) {
        this.certificateEvents = certificateEvents;
    }

    /** SCHEDULED or MANUAL for each certificate a renewal produced; certificates issued directly are absent. */
    private Map<String, String> renewalTriggers(Long organizationId, List<CertificateEntity> certs) {
        if (certificateEvents == null || certs.isEmpty()) {
            return Map.of();
        }
        List<String> xrefs = certs.stream().map(CertificateEntity::getCertificateXref).toList();
        Map<String, String> triggers = new java.util.HashMap<>();
        for (Object[] row : certificateEvents.findRenewalSources(organizationId, xrefs)) {
            String trigger = EventSource.SCHEDULER.value().equals(row[1]) ? "SCHEDULED" : "MANUAL";
            triggers.put((String) row[0], trigger);
        }
        return triggers;
    }

    @PostMapping(Paths.CERTS_CONVERT_TO_AUTOMATED)
    @FeatureGated(FeatureFlags.CERTIFICATE_ISSUANCE)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_CONVERTED_TO_AUTOMATED, target = "#certXref")
    @Operation(summary = "Convert a certificate/domain from manual flow to automated flow")
    public ResponseEntity<Map<String, Object>> convertToAutomated(
            @PathVariable String certXref,
            @Valid @RequestBody ConvertToAutomatedRequest request) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        Map<String, Object> result = certConversionService.convertToAutomated(resolvedOrgId, certXref, request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(result);
    }

    // ------------------------------------------------------------------ //
    //  Manual issuance flow
    // ------------------------------------------------------------------ //

    @PostMapping(Paths.CERT_ISSUE_MANUAL)
    @FeatureGated(FeatureFlags.CERTIFICATE_MANUAL_ISSUANCE)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_MANUAL_ISSUE_REQUESTED, name = "#req.domain")
    @Operation(summary = "Initiate manual certificate issuance — no DNS provider credential required (async, 202 Accepted)")
    public ResponseEntity<Map<String, Object>> issueManual(
            @Valid @RequestBody IssueManualRequest req) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        CertificateEntity cert = certManualIssuanceService.initiateManualIssuance(resolvedOrgId, req);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of(
                "certificateXref", cert.getCertificateXref(),
                "domain",          cert.getDomain(),
                "status",          cert.getStatus(),
                "submittedAt",     OffsetDateTime.now(ZoneOffset.UTC).toString()
        ));
    }

    @GetMapping(Paths.CERT_TXT_RECORDS)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_READ + "')")
    @Operation(summary = "Get DNS TXT records to add for manual certificate issuance (poll until status=AWAITING_DNS)")
    public ResponseEntity<Map<String, Object>> getTxtRecords(
            @PathVariable String certXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        List<TxtRecordDto> records = certManualIssuanceService.getTxtRecords(certXref, resolvedOrgId);

        return ResponseEntity.ok(Map.of("txtRecords", records));
    }

    @PostMapping(Paths.CERT_VALIDATE_DNS)
    @FeatureGated(FeatureFlags.CERTIFICATE_MANUAL_ISSUANCE)
    @PreAuthorize("hasPermission(null, '" + CERTIFICATE_ISSUE + "')")
    @AuditFailure(value = AuditEventType.CERTIFICATE_DNS_VALIDATED, target = "#certXref")
    @Operation(summary = "Trigger DNS validation — sends CERT_MANUAL_DNS_VALIDATE to agent (async, 202 Accepted)")
    public ResponseEntity<Void> validateDns(
            @PathVariable String certXref) {
        Long resolvedOrgId = OrgResolver.fromJwt();

        certManualIssuanceService.triggerValidation(certXref, resolvedOrgId);
        return ResponseEntity.accepted().build();
    }

    // ------------------------------------------------------------------ //
    //  Mappers
    // ------------------------------------------------------------------ //

    /**
     * The CERTIFICATE_DOWNLOAD flag for the org this response serves, through the same org-scoped
     * resolver {@code @FeatureGated} uses. Called once per request, never per row.
     */
    private boolean isCertificateDownloadEnabled(Long servedOrganizationId) {
        return featureFlagService.isEnabled(FeatureFlags.CERTIFICATE_DOWNLOAD, servedOrganizationId);
    }

    private Map<String, Object> toCertResponse(CertificateEntity cert, boolean downloadEnabled) {
        Map<String, Object> m = new LinkedHashMap<>();
        CertIssuanceService.CredentialRefs refs = certIssuanceService.resolveCredentialRefsForResponse(cert);

        m.put("certificateXref",    cert.getCertificateXref());
        m.put("userDomainCertId",   cert.getUserDomainCertId());
        m.put("domain",             cert.getDomain());
        m.put("caProvider",         cert.getCaProvider());
        m.put("status",             cert.getStatus());
        m.put("wildcard",           cert.getWildcard());
        m.put("san",                cert.getSan());
        m.put("sanDomains",         cert.getSanDomains() != null ? cert.getSanDomains() : new String[0]);
        m.put("dnsConfigXref",      refs.dnsConfigXref());
        m.put("deploymentCredentialXrefs", refs.deploymentCredentialXrefs());
        m.put("dnsCredentialKvPath", refs.dnsCredentialKvPath());
        m.put("deploymentCredentialKvPaths", refs.deploymentCredentialKvPaths());
        if (cert.getCertSecretHandle() != null) {
            m.put("certSecretHandle", cert.getCertSecretHandle());
        }
        if (cert.getTargetResourceId() != null)     m.put("targetResourceId",   cert.getTargetResourceId());
        if (cert.getIssuer() != null)             m.put("issuer",             cert.getIssuer());
        if (cert.getSerialNumber() != null)        m.put("serialNumber",       cert.getSerialNumber());
        if (cert.getFingerprintSha256() != null)   m.put("fingerprintSha256",  cert.getFingerprintSha256());
        if (cert.getValidFrom() != null)           m.put("validFrom",          cert.getValidFrom().toString());
        if (cert.getValidTo() != null)             m.put("validTo",            cert.getValidTo().toString());
        if (cert.getSignatureAlgorithm() != null)  m.put("signatureAlgorithm", cert.getSignatureAlgorithm());
        if (cert.getPublicKeyAlgorithm() != null)  m.put("publicKeyAlgorithm", cert.getPublicKeyAlgorithm());
        if (cert.getKeySize() != null)             m.put("keySize",            cert.getKeySize());
        if (cert.getCertType() != null)            m.put("certType",           cert.getCertType());
        // Raw lastErrorCode/lastErrorMessage are intentionally NOT exposed — they may carry
        // internal system detail. Surface only a sanitized, user-facing message derived from
        // the code. The raw values remain in the database for internal logs/alerts/audit.
        if (cert.getLastErrorCode() != null)           m.put("userMessage",            UserFacingErrorMessages.forCode(cert.getLastErrorCode()));
        if (cert.getLastErrorAt() != null)             m.put("lastErrorAt",            cert.getLastErrorAt().toString());
        if (cert.getCorrelationId() != null)           m.put("correlationId",          cert.getCorrelationId());
        if (cert.getOrderId() != null)                 m.put("orderId",                cert.getOrderId());
        if (cert.getSpecialCertificateType() != null)  m.put("specialCertificateType", cert.getSpecialCertificateType());
        m.put("keyCustody", cert.getKeyCustody());
        if (cert.getCaAccountSource() != null)         m.put("caAccountSource",        cert.getCaAccountSource());
        if (cert.getCaOrderCost() != null)             m.put("caOrderCost",            cert.getCaOrderCost());
        if (cert.getCaOrderCurrency() != null)         m.put("caOrderCurrency",        cert.getCaOrderCurrency());
        m.put("export", toExportView(certExportEligibilityPolicy.evaluate(cert, downloadEnabled),
                CallerPermissions.current()));
        return m;
    }

    /**
     * Built as a map so {@code reason} serialises as an explicit null when export is available.
     * {@code formats} lists only what this caller may download, so the key formats drop out without
     * {@code certificate:deploy}; {@code available} still reflects the certificate, since the
     * certificate and chain formats are open to every reader.
     */
    private static Map<String, Object> toExportView(CertExportEligibility eligibility, Set<String> callerPermissions) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("available", eligibility.available());
        view.put("reason",    eligibility.reason() != null ? eligibility.reason().name() : null);
        view.put("formats",   eligibility.formats().stream()
                .filter(format -> format.isPermittedFor(callerPermissions))
                .toList());
        return view;
    }

    private Map<String, Object> toCertSummary(CertificateEntity cert, CertIssuanceService.CredentialRefs refs,
                                              boolean downloadEnabled) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (refs == null) {
            refs = certIssuanceService.resolveCredentialRefsForResponse(cert);
        }

        m.put("certificateXref", cert.getCertificateXref());
        m.put("userDomainCertId", cert.getUserDomainCertId());
        m.put("domain",          cert.getDomain());
        m.put("caProvider",      cert.getCaProvider());
        m.put("status",          cert.getStatus());
        m.put("wildcard",        cert.getWildcard());
        m.put("san",             cert.getSan());
        m.put("sanDomains",      cert.getSanDomains() != null ? cert.getSanDomains() : new String[0]);
        m.put("dnsConfigXref",      refs.dnsConfigXref());
        m.put("deploymentCredentialXrefs", refs.deploymentCredentialXrefs());
        m.put("dnsCredentialKvPath", refs.dnsCredentialKvPath());
        m.put("deploymentCredentialKvPaths", refs.deploymentCredentialKvPaths());
        if (cert.getTargetResourceId() != null) m.put("targetResourceId", cert.getTargetResourceId());
        if (cert.getIssuer() != null)                  m.put("issuer",                 cert.getIssuer());
        if (cert.getValidFrom() != null)              m.put("validFrom",              cert.getValidFrom().toString());
        if (cert.getValidTo() != null)                 m.put("validTo",                cert.getValidTo().toString());
        if (cert.getSignatureAlgorithm() != null)      m.put("signatureAlgorithm",     cert.getSignatureAlgorithm());
        if (cert.getPublicKeyAlgorithm() != null)      m.put("publicKeyAlgorithm",     cert.getPublicKeyAlgorithm());
        if (cert.getKeySize() != null)                 m.put("keySize",                cert.getKeySize());
        if (cert.getCertType() != null)                m.put("certType",               cert.getCertType());
        if (cert.getSpecialCertificateType() != null)  m.put("specialCertificateType", cert.getSpecialCertificateType());
        m.put("keyCustody", cert.getKeyCustody());
        m.put("exportAvailable", certExportEligibilityPolicy.evaluate(cert, downloadEnabled).available());
        return m;
    }

    private Map<String, Object> toExpiringRow(CertificateRepository.ExpiringCertificateRow row) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("domain", row.getDomain());
        m.put("certificateXref", row.getCertificateXref());
        m.put("validTo", row.getValidTo() != null ? row.getValidTo().toString() : null);
        m.put("status", row.getStatus());
        m.put("caProvider", row.getCaProvider());
        return m;
    }
}
