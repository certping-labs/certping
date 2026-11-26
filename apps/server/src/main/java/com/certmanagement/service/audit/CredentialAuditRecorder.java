// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.audit;

import com.certmanagement.audit.AuditChange;
import com.certmanagement.audit.AuditEventType;
import com.certmanagement.audit.AuditEvents;
import com.certmanagement.audit.AuditRecorder;
import com.certmanagement.audit.AuditSubject;
import com.certmanagement.audit.CredentialFields;
import com.certmanagement.entity.CredentialReferenceEntity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Writes the credential events of the audit trail (credentials added, changed and deleted, a DNS credential
 * assigned to a certificate's domain) and the deployment-target events (a deployment credential added to,
 * changed on or removed from a certificate's domain).
 *
 * <p>Each is written in the change's own transaction ({@link AuditRecorder#record}, which requires one), so it
 * commits and rolls back with the change. The row written here is the action's one customer row (the request
 * interceptor's row is an internal {@code api.request} row).
 *
 * <p>No secret reaches a row. The credential details, the secret store location and the scope configuration
 * are named, never valued ({@link CredentialFields}); a deployment target's per-certificate plan likewise. A
 * credential is named by its description and referenced by its xref, its provider is in words, and a provider
 * code no one wrote words for is kept only when it looks like a code.
 */
@Component
public class CredentialAuditRecorder {

    /** Where a new credential's secret is kept: in CertPing's secret store, in the customer's own, or nowhere. */
    public enum StoredIn {
        /** The credential details were pasted and CertPing keeps them. */
        CERTPING,
        /** A secret store location of the customer's was given. */
        OWN_STORE,
        /** An ambient identity (workload identity, instance profile, in-cluster account) needs no secret. */
        NOT_NEEDED
    }

    private static final Pattern CODE = Pattern.compile("^[A-Z][A-Z0-9_]{0,39}$");

    private static final Map<String, String> PROVIDERS = Map.ofEntries(
            // DNS providers.
            Map.entry("AWS_ROUTE53", "Amazon Route 53"),
            Map.entry("CLOUDFLARE", "Cloudflare"),
            Map.entry("GODADDY", "GoDaddy"),
            Map.entry("NAMECHEAP", "Namecheap"),
            Map.entry("NAMEDOTCOM", "Name.com"),
            Map.entry("HOSTINGER", "Hostinger"),
            Map.entry("CERTPING", "CertPing"),
            // Deployment targets.
            Map.entry("AZURE_KV", "Azure Key Vault"),
            Map.entry("AZURE_APP_GW", "Azure Application Gateway"),
            Map.entry("AZURE_APP_GW_CONTAINERS", "Azure Application Gateway for Containers"),
            Map.entry("AZURE_AFD", "Azure Front Door"),
            Map.entry("AWS_ACM", "AWS Certificate Manager"),
            Map.entry("AWS_ALB", "AWS Application Load Balancer"),
            Map.entry("AWS_NLB", "AWS Network Load Balancer"),
            Map.entry("AWS_API_GW_REST", "Amazon API Gateway (REST)"),
            Map.entry("AWS_API_GW_HTTP", "Amazon API Gateway (HTTP)"),
            Map.entry("AWS_CLOUDFRONT", "Amazon CloudFront"),
            Map.entry("AWS_ORGANIZATION", "AWS Organization"),
            Map.entry("GCP_CERT_MANAGER", "Google Certificate Manager"),
            Map.entry("GCP_ALB", "Google Cloud Load Balancer"),
            Map.entry("GCP_PROXY_NLB", "Google Cloud Network Load Balancer"),
            Map.entry("GCP_API_GW", "Google API Gateway"),
            Map.entry("GCP_CLOUD_CDN", "Google Cloud CDN"),
            Map.entry("CLOUDFLARE_EDGE", "Cloudflare"),
            Map.entry("KUBERNETES_SECRETS", "Kubernetes"),
            Map.entry("AKAMAI_CPS", "Akamai"),
            Map.entry("F5_BIGIP", "F5 BIG-IP"));

    private final AuditRecorder recorder;

    public CredentialAuditRecorder(AuditRecorder recorder) {
        this.recorder = recorder;
    }

    // ── Credentials ──────────────────────────────────────────────────────

    /**
     * {@code credential} was added.
     *
     * @param storedIn where its secret is kept
     * @param authMode how a deployment credential authenticates (e.g. {@code WORKLOAD_IDENTITY}); null when unset
     */
    public void credentialCreated(CredentialReferenceEntity credential, StoredIn storedIn, String authMode) {
        Map<String, String> attributes = typeOf(credential);
        put(attributes, "storedIn", storedIn == null ? null : storedIn.name());
        put(attributes, "authMode", code(authMode));
        recorder.record(AuditEvents.success(AuditEventType.CREDENTIAL_CREATED,
                subject(credential).attributes(attributes).build()));
    }

    /**
     * {@code credential} was changed.
     *
     * @param changedFields the {@link CredentialFields} that were supplied: kept by name, never valued
     * @param authMode      the deployment credential's authentication mode after the change; null when unset
     */
    public void credentialUpdated(CredentialReferenceEntity credential, Collection<String> changedFields,
                                  String authMode) {
        List<AuditChange> changes = new ArrayList<>();
        for (String field : changedFields) {
            if (CredentialFields.KEPT_BY_NAME.contains(field)) {
                changes.add(new AuditChange(field, null, null));
            }
        }
        Map<String, String> attributes = typeOf(credential);
        put(attributes, "authMode", code(authMode));
        recorder.record(AuditEvents.success(AuditEventType.CREDENTIAL_UPDATED,
                subject(credential).changes(changes).attributes(attributes).build()));
    }

    /**
     * {@code credential} was deleted.
     *
     * @param configurationsCleared how many domain and deployment configurations still named it and were cleared
     */
    public void credentialDeleted(CredentialReferenceEntity credential, int configurationsCleared) {
        Map<String, String> attributes = typeOf(credential);
        if (configurationsCleared > 0) {
            put(attributes, "configurationsCleared", Integer.toString(configurationsCleared));
        }
        recorder.record(AuditEvents.success(AuditEventType.CREDENTIAL_DELETED,
                subject(credential).attributes(attributes).build()));
    }

    /**
     * The DNS credential {@code credential} now validates {@code targetDomain} of the certificate for
     * {@code certificateDomain}, in place of the credential {@code previousXref} (null when it had none).
     */
    public void dnsCredentialAssigned(CredentialReferenceEntity credential, String certificateDomain,
                                      String targetDomain, String previousXref) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "certificateDomain", certificateDomain);
        recorder.record(AuditEvents.success(AuditEventType.DNS_CREDENTIAL_ASSIGNED, subject(credential)
                .domain(targetDomain)
                .changes(List.of(new AuditChange("credential", previousXref, credential.getCredentialXref())))
                .attributes(attributes)
                .build()));
    }

    // ── Deployment targets ───────────────────────────────────────────────

    /** The deployment credential {@code credential} was added to {@code domain}'s certificate; with a plan when {@code withTargets}. */
    public void deploymentTargetAdded(CredentialReferenceEntity credential, String domain, boolean withTargets) {
        recorder.record(AuditEvents.success(AuditEventType.DEPLOYMENT_TARGET_ADDED, subject(credential).domain(domain)
                .attributes(withTargets ? targetsByName() : Map.of()).build()));
    }

    /** The plan of {@code domain}'s deployment target {@code credential} was replaced. */
    public void deploymentTargetUpdated(CredentialReferenceEntity credential, String domain) {
        recorder.record(AuditEvents.success(AuditEventType.DEPLOYMENT_TARGET_UPDATED, subject(credential)
                .domain(domain).changes(List.of(new AuditChange("targets", null, null))).build()));
    }

    /**
     * The deployment target {@code credentialXref} was removed from {@code domain}'s certificate.
     *
     * @param credential the credential, or null when it no longer exists
     */
    public void deploymentTargetRemoved(Long organizationId, String credentialXref,
                                        CredentialReferenceEntity credential, String domain) {
        AuditSubject.AuditSubjectBuilder subject = credential != null ? subject(credential)
                : AuditSubject.builder().organizationId(organizationId).resourceRef(credentialXref);
        recorder.record(AuditEvents.success(AuditEventType.DEPLOYMENT_TARGET_REMOVED, subject.domain(domain).build()));
    }

    /**
     * The provider in words: "Cloudflare", "Azure Key Vault". A code this build has no words for is kept as it is
     * when it looks like a code; anything else a caller typed is left out.
     */
    public static String providerName(String provider) {
        if (provider == null || provider.isBlank()) {
            return null;
        }
        String code = provider.trim().toUpperCase(Locale.ROOT);
        String words = PROVIDERS.get(code);
        return words != null ? words : CODE.matcher(code).matches() ? code : null;
    }

    private static AuditSubject.AuditSubjectBuilder subject(CredentialReferenceEntity credential) {
        return AuditSubject.builder()
                .organizationId(credential.getOrganizationId())
                .resourceId(credential.getId())
                .resourceRef(credential.getCredentialXref())
                .name(credential.getDescription())
                .provider(providerName(credential.getProvider()));
    }

    private static Map<String, String> typeOf(CredentialReferenceEntity credential) {
        Map<String, String> attributes = new LinkedHashMap<>();
        put(attributes, "credentialType", code(credential.getType()));
        return attributes;
    }

    /** The plan named, never valued (the catalog keeps {@code targets} by name only). */
    private static Map<String, String> targetsByName() {
        Map<String, String> attributes = new LinkedHashMap<>();
        attributes.put("targets", "supplied");
        return attributes;
    }

    /** {@code value} when it looks like an enum code; null otherwise, so free text never becomes an attribute. */
    private static String code(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return CODE.matcher(trimmed).matches() ? trimmed : null;
    }

    private static void put(Map<String, String> attributes, String name, String value) {
        if (value != null && !value.isBlank()) {
            attributes.put(name, value);
        }
    }
}
