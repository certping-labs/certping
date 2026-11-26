// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.CertificateAuthoritiesResponse;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse.AcmeView;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse.AgentView;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse.Authority;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse.CredentialView;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.enums.CaProvider;
import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.service.cert.CredentialReferenceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Every CA an organization can issue from, with where it is configured: the agents' reported CA
 * status for Let's Encrypt and GlobalSign, the organization's own credentials for DigiCert.
 *
 * <p>Built only from metadata. The agent status is parsed into {@link AgentCaStatus}, which has no
 * field for a key, and a credential shows its xref, description and dates, never its secret.
 */
@Service
@RequiredArgsConstructor
public class CertificateAuthorityService {

    public static final String DOCS_PATH = "docs/integrations.md#certificate-authorities";

    static final String CONFIGURED = "CONFIGURED";
    static final String NOT_CONFIGURED = "NOT_CONFIGURED";
    static final String UNKNOWN = "UNKNOWN";
    /** The agent of a heartbeat that carried no token stamp. */
    static final String UNIDENTIFIED_AGENT_ID = "unidentified";

    private final AgentCaStatusStore caStatusStore;
    private final CredentialReferenceService credentialService;

    public CertificateAuthoritiesResponse list(long organizationId) {
        List<AgentCaStatusStore.AgentReport> reports = caStatusStore.list(organizationId).stream()
                .filter(r -> r.caStatus() != null)
                .toList();
        List<CredentialReferenceEntity> digicert = credentialService.listCa(organizationId).stream()
                .filter(c -> CaProvider.DIGICERT.name().equals(c.getProvider()))
                .toList();
        String org = String.valueOf(organizationId);
        return new CertificateAuthoritiesResponse(List.of(
                letsEncrypt(reports, org),
                digiCert(digicert),
                agentConfigured(CaProvider.GLOBALSIGN, "GlobalSign Atlas", reports, AgentCaStatus::getGlobalsign)));
    }

    private Authority letsEncrypt(List<AgentCaStatusStore.AgentReport> reports, String organizationId) {
        List<AgentView> agents = reports.stream().map(r -> {
            AgentCaStatus.Acme acme = r.caStatus().getAcme();
            boolean configured = acme != null && acme.getDirectoryUrl() != null && !acme.getDirectoryUrl().isBlank();
            return agent(r, configured, configured ? acmeView(acme, organizationId) : null);
        }).toList();
        return new Authority(CaProvider.LETS_ENCRYPT.name(), "Let's Encrypt (ACME)", "ACME",
                agentStatus(agents), "AGENT", "TESTED", agents, List.of(), DOCS_PATH);
    }

    private static AcmeView acmeView(AgentCaStatus.Acme acme, String organizationId) {
        // Only this organization's account: an agent never reports another's, but the filter holds regardless.
        AgentCaStatus.AcmeAccount account = acme.getAccounts() == null ? null : acme.getAccounts().stream()
                .filter(Objects::nonNull)
                .filter(a -> organizationId.equals(a.getOrganizationId()))
                .findFirst()
                .orElse(null);
        return new AcmeView(acme.getDirectoryUrl(), environment(acme.getEnvironment()),
                acme.getContactEmail() == null ? "" : acme.getContactEmail(),
                account == null ? null : account.getAccountUrl(),
                account == null ? null : account.getKeyType(),
                account == null ? null : account.getCreatedAt());
    }

    private static String environment(String reported) {
        return "PRODUCTION".equals(reported) || "STAGING".equals(reported) ? reported : "CUSTOM";
    }

    private Authority digiCert(List<CredentialReferenceEntity> credentials) {
        List<CredentialView> views = credentials.stream()
                .map(c -> new CredentialView(c.getCredentialXref(), c.getDescription(),
                        c.getCreatedAt() == null ? null : c.getCreatedAt().toString(),
                        c.getUpdatedAt() == null ? null : c.getUpdatedAt().toString()))
                .toList();
        return new Authority(CaProvider.DIGICERT.name(), "DigiCert CertCentral", "API",
                views.isEmpty() ? NOT_CONFIGURED : CONFIGURED, "ORGANIZATION", "BETA", List.of(), views, DOCS_PATH);
    }

    private Authority agentConfigured(CaProvider ca, String name, List<AgentCaStatusStore.AgentReport> reports,
                                      Function<AgentCaStatus, AgentCaStatus.Configured> part) {
        List<AgentView> agents = reports.stream().map(r -> {
            AgentCaStatus.Configured c = part.apply(r.caStatus());
            return agent(r, c != null && c.isConfigured(), null);
        }).toList();
        return new Authority(ca.name(), name, "API", agentStatus(agents), "AGENT", "BETA", agents, List.of(),
                DOCS_PATH);
    }

    private static String agentStatus(List<AgentView> agents) {
        if (agents.isEmpty()) {
            return UNKNOWN;
        }
        return agents.stream().anyMatch(AgentView::configured) ? CONFIGURED : NOT_CONFIGURED;
    }

    private static AgentView agent(AgentCaStatusStore.AgentReport r, boolean configured, AcmeView acme) {
        String id = r.tokenId() == null ? UNIDENTIFIED_AGENT_ID : String.valueOf(r.tokenId());
        String name = r.agentName() == null || r.agentName().isBlank() ? "Agent" : r.agentName();
        return new AgentView(id, name, r.reportedAt() == null ? null : r.reportedAt().toInstant().toString(),
                configured, acme);
    }
}
