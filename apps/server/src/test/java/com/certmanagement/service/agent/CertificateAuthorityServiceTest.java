// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.agent;

import com.certmanagement.dto.agent.CertificateAuthoritiesResponse;
import com.certmanagement.dto.agent.CertificateAuthoritiesResponse.Authority;
import com.certmanagement.entity.CredentialReferenceEntity;
import com.certmanagement.messaging.model.AgentCaStatus;
import com.certmanagement.service.cert.CredentialReferenceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertificateAuthorityServiceTest {

    private static final long ORG = 7L;
    private static final OffsetDateTime SEEN = OffsetDateTime.of(2026, 10, 30, 9, 0, 0, 0, ZoneOffset.UTC);
    private static final ObjectMapper JSON = JsonMapper.builderWithJackson2Defaults().build();
    /** Field names that could carry key material. "keyType" names an algorithm and is allowed. */
    private static final Pattern SECRET_FIELD = Pattern.compile(
            "(?i).*(secret|password|privatekey|private_key|apikey|api_key|keyvalue|key_value|pem|token|credjson|secrethandle).*");

    private AgentCaStatusStore store;
    private CredentialReferenceService credentials;
    private CertificateAuthorityService service;

    @BeforeEach
    void setUp() {
        store = mock(AgentCaStatusStore.class);
        credentials = mock(CredentialReferenceService.class);
        service = new CertificateAuthorityService(store, credentials);
    }

    @Test
    void noAgentReportYet_agentCasAreUnknown_andDigiCertNotConfigured() {
        when(store.list(ORG)).thenReturn(List.of());
        when(credentials.listCa(ORG)).thenReturn(List.of());

        Map<String, Authority> byId = byId(service.list(ORG));

        assertThat(byId.keySet()).containsExactly("LETS_ENCRYPT", "DIGICERT", "GLOBALSIGN");
        assertThat(byId.get("LETS_ENCRYPT").status()).isEqualTo("UNKNOWN");
        assertThat(byId.get("GLOBALSIGN").status()).isEqualTo("UNKNOWN");
        assertThat(byId.get("DIGICERT").status()).isEqualTo("NOT_CONFIGURED");
        assertThat(byId.get("DIGICERT").configuredWhere()).isEqualTo("ORGANIZATION");
        assertThat(byId.get("LETS_ENCRYPT").maturity()).isEqualTo("TESTED");
        assertThat(byId.get("DIGICERT").maturity()).isEqualTo("BETA");
        assertThat(byId.values()).allSatisfy(a -> assertThat(a.docsPath())
                .isEqualTo("docs/integrations.md#certificate-authorities"));
    }

    @Test
    void letsEncrypt_showsOnlyThisOrganizationsAccount_andAccountUrlNullBeforeTheFirstOrder() {
        AgentCaStatus withAccount = status("https://pebble:14000/dir", "CUSTOM", List.of(
                account("999", "https://acme/acct/other"),
                account(String.valueOf(ORG), "https://acme/acct/mine")), true);
        AgentCaStatus noAccount = status("https://acme-v02.api.letsencrypt.org/directory", "PRODUCTION",
                List.of(), false);
        when(store.list(ORG)).thenReturn(List.of(
                new AgentCaStatusStore.AgentReport(11L, "edge-1", withAccount, SEEN),
                new AgentCaStatusStore.AgentReport(null, null, noAccount, SEEN)));
        when(credentials.listCa(ORG)).thenReturn(List.of());

        Map<String, Authority> byId = byId(service.list(ORG));

        Authority le = byId.get("LETS_ENCRYPT");
        assertThat(le.status()).isEqualTo("CONFIGURED");
        assertThat(le.name()).isEqualTo("Let's Encrypt (ACME)");
        assertThat(le.kind()).isEqualTo("ACME");
        assertThat(le.agents()).hasSize(2);
        CertificateAuthoritiesResponse.AgentView first = le.agents().get(0);
        assertThat(first.agentId()).isEqualTo("11");
        assertThat(first.agentName()).isEqualTo("edge-1");
        assertThat(first.lastSeenAt()).isEqualTo("2026-10-30T09:00:00Z");
        assertThat(first.acme().environment()).isEqualTo("CUSTOM");
        assertThat(first.acme().accountUrl()).isEqualTo("https://acme/acct/mine");
        assertThat(first.acme().keyType()).isEqualTo("RSA 2048");
        CertificateAuthoritiesResponse.AgentView second = le.agents().get(1);
        assertThat(second.agentId()).isEqualTo(CertificateAuthorityService.UNIDENTIFIED_AGENT_ID);
        assertThat(second.acme().accountUrl()).isNull();
        assertThat(second.acme().environment()).isEqualTo("PRODUCTION");

        assertThat(byId.get("GLOBALSIGN").status()).isEqualTo("CONFIGURED");
        assertThat(byId.get("GLOBALSIGN").agents()).extracting(CertificateAuthoritiesResponse.AgentView::configured)
                .containsExactly(true, false);
        assertThat(byId.get("GLOBALSIGN").agents()).allSatisfy(a -> assertThat(a.acme()).isNull());
    }

    @Test
    void digiCert_isConfiguredByTheOrganizationsCredentials_listedAsMetadata() {
        when(store.list(ORG)).thenReturn(List.of());
        when(credentials.listCa(ORG)).thenReturn(List.of(CredentialReferenceEntity.builder()
                .credentialXref("cred-dc").organizationId(ORG).provider("DIGICERT").type("CA").status("ACTIVE")
                .description("CertCentral").secretHandle("local:certping-org7-dc")
                .createdAt(SEEN).updatedAt(SEEN).build()));

        Authority dc = byId(service.list(ORG)).get("DIGICERT");

        assertThat(dc.status()).isEqualTo("CONFIGURED");
        assertThat(dc.credentials()).singleElement().satisfies(c -> {
            assertThat(c.credentialXref()).isEqualTo("cred-dc");
            assertThat(c.description()).isEqualTo("CertCentral");
            assertThat(c.createdAt()).isNotNull();
        });
    }

    /**
     * The hard rule: whatever an agent sends and whatever the credential holds, the API
     * response carries no key material and no field that could hold some.
     */
    @Test
    void response_neverContainsKeyMaterial_evenWhenTheAgentPayloadCarriesSome() throws Exception {
        String hostile = """
                {"acme":{"directoryUrl":"https://pebble:14000/dir","environment":"CUSTOM","contactEmail":"",
                  "privateKey":"-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----",
                  "accounts":[{"organizationId":"7","accountUrl":"https://acme/acct/7","keyType":"RSA 2048",
                    "createdAt":"2026-10-01T00:00:00Z","keyPem":"-----BEGIN RSA PRIVATE KEY-----"}]},
                 "otherCa":{"configured":true,"loginPassword":"hunter2"},
                 "globalsign":{"configured":true,"apiKey":"gs-key","apiSecret":"gs-secret"}}
                """;
        AgentCaStatus parsed = JSON.readValue(hostile, AgentCaStatus.class);
        when(store.list(ORG)).thenReturn(List.of(new AgentCaStatusStore.AgentReport(3L, "a", parsed, SEEN)));
        when(credentials.listCa(ORG)).thenReturn(List.of(CredentialReferenceEntity.builder()
                .credentialXref("cred-dc").organizationId(ORG).provider("DIGICERT").type("CA").status("ACTIVE")
                .secretHandle("https://vault/secrets/dc-api-key").configJson("{\"apiKey\":\"dc-secret\"}")
                .build()));

        String body = JSON.writeValueAsString(service.list(ORG));

        assertThat(body).doesNotContain("-----", "PRIVATE KEY", "BEGIN", "hunter2", "gs-key", "gs-secret",
                "dc-secret", "dc-api-key", "MIIE", "otherCa");
        List<String> fields = new ArrayList<>();
        collectFieldNames(JSON.readTree(body), fields);
        assertThat(fields).isNotEmpty().noneMatch(f -> SECRET_FIELD.matcher(f).matches());
        // And the stored form drops the hostile fields too: it is written from the same typed object.
        String stored = JSON.writeValueAsString(parsed);
        assertThat(stored).doesNotContain("PRIVATE KEY", "hunter2", "gs-key", "gs-secret", "keyPem");
    }

    private static void collectFieldNames(JsonNode node, List<String> out) {
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> e : node.properties()) {
                out.add(e.getKey());
                collectFieldNames(e.getValue(), out);
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                collectFieldNames(child, out);
            }
        }
    }

    private static Map<String, Authority> byId(CertificateAuthoritiesResponse response) {
        Map<String, Authority> map = new java.util.LinkedHashMap<>();
        response.authorities().forEach(a -> map.put(a.id(), a));
        return map;
    }

    private static AgentCaStatus.AcmeAccount account(String org, String url) {
        return AgentCaStatus.AcmeAccount.builder().organizationId(org).accountUrl(url).keyType("RSA 2048")
                .createdAt("2026-10-01T00:00:00Z").build();
    }

    private static AgentCaStatus status(String directory, String env, List<AgentCaStatus.AcmeAccount> accounts,
                                        boolean globalsign) {
        return AgentCaStatus.builder()
                .acme(AgentCaStatus.Acme.builder().directoryUrl(directory).environment(env).contactEmail("ops@x")
                        .accounts(accounts).build())
                .globalsign(new AgentCaStatus.Configured(globalsign))
                .build();
    }
}
