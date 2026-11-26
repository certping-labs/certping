// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.cloud.gcp.GcpAuthMode;
import com.certping.agent.deployment.cloud.gcp.GcpAuthScope;
import com.certping.agent.deployment.cloud.gcp.GcpAuthSecret;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.message.CertDeploymentMessage;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GcpDeploymentSupportTest {

    private final ObjectMapper om = JsonMapper.builderWithJackson2Defaults().build();

    // ===================== mergeCertificateLists =====================

    @Test
    void mergeCertificateLists_prependsNewPreservesOrder() {
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("new",
                List.of("old-a", "old-b"));
        assertThat(merged).containsExactly("new", "old-a", "old-b");
    }

    @Test
    void mergeCertificateLists_dropsBlankAndNull() {
        List<String> existing = new java.util.ArrayList<>();
        existing.add("old-a");
        existing.add(null);
        existing.add("");
        existing.add(" ");
        existing.add("old-b");
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("new", existing);
        assertThat(merged).containsExactly("new", "old-a", "old-b");
    }

    @Test
    void mergeCertificateLists_excludesPriorToRemove() {
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("new",
                List.of("prior", "keeper"), "prior");
        assertThat(merged).containsExactly("new", "keeper");
    }

    @Test
    void mergeCertificateLists_blankNewCert_skipped() {
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("", List.of("a", "b"));
        assertThat(merged).containsExactly("a", "b");
        List<String> merged2 = GcpDeploymentSupport.mergeCertificateLists(null, List.of("a", "b"));
        assertThat(merged2).containsExactly("a", "b");
    }

    @Test
    void mergeCertificateLists_nullExisting_returnsJustNew() {
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("new", null);
        assertThat(merged).containsExactly("new");
    }

    @Test
    void mergeCertificateLists_dedupesDuplicate() {
        List<String> merged = GcpDeploymentSupport.mergeCertificateLists("new",
                List.of("new", "other"));
        assertThat(merged).containsExactly("new", "other");
    }

    // ===================== mergeAndPruneByLineage =====================

    private static final String P = "https://www.googleapis.com/compute/v1/projects/p/global/sslCertificates/";

    @Test
    void mergeAndPruneByLineage_prunesAllStaleVersionsOfSameLineage() {
        String base = "example-project";
        String newCert = P + base + "-20260617220546";
        List<String> existing = List.of(
                P + base + "-20260617220126",   // older version of THIS lineage → prune
                P + base + "-20260616010101",   // even older version → prune
                P + "abc-example-net-9313729890-20260619015153"); // different domain → keep

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(newCert, existing, base, null);

        assertThat(prune.desired()).containsExactly(
                newCert,
                P + "abc-example-net-9313729890-20260619015153");
        assertThat(prune.toDelete()).containsExactlyInAnyOrder(
                P + base + "-20260617220126",
                P + base + "-20260616010101");
    }

    @Test
    void mergeAndPruneByLineage_keepsOtherDomains() {
        String base = "shop-example-net-12634913843772";
        String newCert = P + base + "-20260701045055";
        List<String> existing = List.of(
                P + "example-project-20260617220126",
                P + "example-org-0327674794-20260619030027",
                P + "certping-placeholder");

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(newCert, existing, base, null);

        // Nothing shares this lineage → nothing pruned; all other certs preserved.
        assertThat(prune.toDelete()).isEmpty();
        assertThat(prune.desired()).containsExactly(
                newCert,
                P + "example-project-20260617220126",
                P + "example-org-0327674794-20260619030027",
                P + "certping-placeholder");
    }

    @Test
    void mergeAndPruneByLineage_alsoPrunesExplicitPriorWithDifferentBase() {
        // Cross-renewal: prior cert used a different xref (different base name) but is passed
        // explicitly via configJson — it must still be pruned even though the lineage prefix differs.
        String base = "shop-example-net-newxref0001";
        String newCert = P + base + "-20260701045055";
        String prior = P + "shop-example-net-oldxref9999-20260601010101";
        List<String> existing = List.of(prior, P + "b-example-net-6717678088-20260616200517");

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(newCert, existing, base, prior);

        assertThat(prune.toDelete()).containsExactly(prior);
        assertThat(prune.desired()).containsExactly(
                newCert, P + "b-example-net-6717678088-20260616200517");
    }

    @Test
    void mergeAndPruneByLineage_ignoresPrefixCollisionWithoutTimestampSuffix() {
        // A cert whose name starts with the base but isn't a real "base-<14 digits>" sibling
        // (e.g. a longer base name) must NOT be pruned.
        String base = "example-project";
        String newCert = P + base + "-20260617220546";
        String notASibling = P + base + "-extra-20260617220126"; // extra segment, not 14-digit suffix

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(
                        newCert, List.of(notASibling), base, null);

        assertThat(prune.toDelete()).isEmpty();
        assertThat(prune.desired()).containsExactly(newCert, notASibling);
    }

    @Test
    void mergeAndPruneByLineage_nullBaseAndNullPrior_keepsEverything() {
        String newCert = P + "x-1-20260701045055";
        List<String> existing = List.of(P + "y-2-20260601010101");

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(newCert, existing, null, null);

        assertThat(prune.toDelete()).isEmpty();
        assertThat(prune.desired()).containsExactly(newCert, P + "y-2-20260601010101");
    }

    @Test
    void mergeAndPruneByLineage_deletesOrphanedPriorNotOnProxy() {
        // Prior cert was already detached from the proxy but never deleted — an orphan that still
        // consumes the per-project quota. It must be retired even though it isn't in `existing`.
        String base = "shop-example-net-newxref0001";
        String newCert = P + base + "-20260701045055";
        String orphanPrior = P + "shop-example-net-oldxref9999-20260601010101";

        GcpDeploymentSupport.CertificatePrune prune = GcpDeploymentSupport.mergeAndPruneByLineage(
                newCert, List.of(P + "other-domain-1111111111-20260619015153"), base, orphanPrior);

        assertThat(prune.toDelete()).containsExactly(orphanPrior);
        assertThat(prune.desired()).containsExactly(
                newCert, P + "other-domain-1111111111-20260619015153");
    }

    @Test
    void mergeAndPruneByLineage_matchesPriorAcrossUrlAndPartialForm() {
        // configJson may store the prior as a partial resource name while the proxy lists the full
        // self-link (or vice versa) — comparison by bare cert name must still match and prune it.
        String base = "example-project";
        String newCert = P + base + "-20260701045055";
        String priorPartial = "projects/p/global/sslCertificates/legacy-cert-20260601010101";
        String priorFullOnProxy = P + "legacy-cert-20260601010101";

        GcpDeploymentSupport.CertificatePrune prune = GcpDeploymentSupport.mergeAndPruneByLineage(
                newCert, List.of(priorFullOnProxy), base, priorPartial);

        assertThat(prune.toDelete()).containsExactly(priorFullOnProxy);
        assertThat(prune.desired()).containsExactly(newCert);
    }

    @Test
    void mergeAndPruneByLineage_priorSameAsNew_notDeleted() {
        String base = "example-project";
        String newCert = P + base + "-20260701045055";

        GcpDeploymentSupport.CertificatePrune prune =
                GcpDeploymentSupport.mergeAndPruneByLineage(newCert, List.of(), base, newCert);

        assertThat(prune.toDelete()).isEmpty();
        assertThat(prune.desired()).containsExactly(newCert);
    }

    // ===================== resolveCertificateBaseName =====================

    @Test
    void resolveCertificateBaseName_prefersDomainMap() {
        Map<String, String> map = new HashMap<>();
        map.put("api.example.com", "my-base");
        assertThat(GcpDeploymentSupport.resolveCertificateBaseName(
                "api.example.com", map, "fallback")).isEqualTo("my-base");
    }

    @Test
    void resolveCertificateBaseName_blankMapValue_fallsBack() {
        Map<String, String> map = new HashMap<>();
        map.put("api.example.com", " ");
        assertThat(GcpDeploymentSupport.resolveCertificateBaseName(
                "api.example.com", map, "fallback")).isEqualTo("fallback");
    }

    @Test
    void resolveCertificateBaseName_fallsBackToCertificateName() {
        assertThat(GcpDeploymentSupport.resolveCertificateBaseName(
                null, null, "only-name")).isEqualTo("only-name");
    }

    @Test
    void resolveCertificateBaseName_allBlank_returnsNull() {
        assertThat(GcpDeploymentSupport.resolveCertificateBaseName(null, null, null)).isNull();
        assertThat(GcpDeploymentSupport.resolveCertificateBaseName(null, null, "")).isNull();
    }

    // ===================== resolveHostname =====================

    @Test
    void resolveHostname_prefersExplicit() {
        assertThat(GcpDeploymentSupport.resolveHostname("h.example.com", "other.com"))
                .isEqualTo("h.example.com");
    }

    @Test
    void resolveHostname_blankExplicit_returnsDomain() {
        assertThat(GcpDeploymentSupport.resolveHostname(null, "other.com")).isEqualTo("other.com");
        assertThat(GcpDeploymentSupport.resolveHostname("", "other.com")).isEqualTo("other.com");
        assertThat(GcpDeploymentSupport.resolveHostname("   ", "other.com")).isEqualTo("other.com");
    }

    // ===================== requireDeploymentHandle =====================

    @Test
    void requireDeploymentHandle_blank_throws() {
        assertThatThrownBy(() -> GcpDeploymentSupport.requireDeploymentHandle(" ", "GCP ALB"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CREDENTIAL_MISSING");
        assertThatThrownBy(() -> GcpDeploymentSupport.requireDeploymentHandle(null, "GCP ALB"))
                .isInstanceOf(PermanentAgentException.class);
    }

    @Test
    void requireDeploymentHandle_present_doesNotThrow() {
        assertThatNoException().isThrownBy(() ->
                GcpDeploymentSupport.requireDeploymentHandle("https://kv/x", "ctx"));
    }

    // ===================== targetProxyResultConfigJson =====================

    @Test
    void targetProxyResultConfigJson_serializes() throws Exception {
        String json = GcpDeploymentSupport.targetProxyResultConfigJson(
                om,
                "projects/p/locations/global/certificates/x",
                "proxy-1",
                "entry-1",
                "api.example.com");
        assertThat(json).contains("certificateResourceName").contains("proxy-1").contains("hostname");
        assertThat(om.readTree(json).get("hostname").asString()).isEqualTo("api.example.com");
    }

    @Test
    void targetProxyResultConfigJson_omitsBlankEntries() throws Exception {
        String json = GcpDeploymentSupport.targetProxyResultConfigJson(
                om, "cert", "proxy", "", null);
        assertThat(json).doesNotContain("certificateMapEntryName").doesNotContain("hostname");
        assertThat(om.readTree(json).get("certificateResourceName").asString()).isEqualTo("cert");
    }

    // ===================== certificateManagerResultConfigJson =====================

    @Test
    void certificateManagerResultConfigJson_full() throws Exception {
        String json = GcpDeploymentSupport.certificateManagerResultConfigJson(
                om, "cert-x", "map-1", "entry-1", "api.x");
        assertThat(json).contains("certificateMap").contains("certificateMapEntryName").contains("hostname");
    }

    @Test
    void certificateManagerResultConfigJson_minimal_omitsBlank() throws Exception {
        String json = GcpDeploymentSupport.certificateManagerResultConfigJson(
                om, "cert-x", null, "", " ");
        assertThat(json).doesNotContain("certificateMap").doesNotContain("Entry").doesNotContain("hostname");
    }

    // ===================== readPriorCertResourceName =====================

    @Test
    void readPriorCertResourceName_blank_returnsNull() {
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om, null, "field")).isNull();
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om, "", "field")).isNull();
    }

    @Test
    void readPriorCertResourceName_unparseable_returnsNull() {
        // Bad JSON — caught + logged → null.
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om, "not-json", "field")).isNull();
    }

    @Test
    void readPriorCertResourceName_missingField_returnsNull() {
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om,
                "{\"other\":\"v\"}", "field")).isNull();
    }

    @Test
    void readPriorCertResourceName_present_returnsValue() {
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om,
                "{\"certificateName\":\"x\"}", "certificateName")).isEqualTo("x");
    }

    @Test
    void readPriorCertResourceName_blankTextual_returnsNull() {
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om,
                "{\"certificateName\":\" \"}", "certificateName")).isNull();
    }

    @Test
    void readPriorCertResourceName_nonTextual_returnsNull() {
        assertThat(GcpDeploymentSupport.readPriorCertResourceName(om,
                "{\"certificateName\":123}", "certificateName")).isNull();
    }

    // ===================== resolveDomain =====================

    @Test
    void resolveDomain_usesMessageDomain() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setDomain("tls.example.com");
        CertificateBundle bundle = new CertificateBundle(
                "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----",
                "-----BEGIN CERTIFICATE-----\ny\n-----END CERTIFICATE-----",
                null,
                null);
        assertThat(GcpDeploymentSupport.resolveDomain(msg, bundle, "test")).isEqualTo("tls.example.com");
    }

    @Test
    void resolveDomain_messageBlank_noLeafDomain_throws() {
        CertDeploymentMessage msg = new CertDeploymentMessage();
        msg.setDomain("");
        CertificateBundle bundle = new CertificateBundle("k", "not-a-pem", null, "not-a-pem");
        assertThatThrownBy(() -> GcpDeploymentSupport.resolveDomain(msg, bundle, "test"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_DOMAIN_REQUIRED");
    }

    // ===================== GcpScopeSupport tests =====================
    // GcpScopeSupport doesn't have a dedicated test file; covered here to lift package coverage.

    @Test
    void scopeSupport_parseAuthMode_validUpperCase() {
        assertThat(GcpScopeSupport.parseAuthMode("WORKLOAD_IDENTITY", "ctx"))
                .isEqualTo(GcpAuthMode.WORKLOAD_IDENTITY);
    }

    @Test
    void scopeSupport_parseAuthMode_validLowerCase() {
        assertThat(GcpScopeSupport.parseAuthMode("workload_identity", "ctx"))
                .isEqualTo(GcpAuthMode.WORKLOAD_IDENTITY);
    }

    @Test
    void scopeSupport_parseAuthMode_blank_throws() {
        assertThatThrownBy(() -> GcpScopeSupport.parseAuthMode(null, "ctx"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CREDENTIAL_INVALID");
        assertThatThrownBy(() -> GcpScopeSupport.parseAuthMode("  ", "ctx"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CREDENTIAL_INVALID");
    }

    @Test
    void scopeSupport_parseAuthMode_unknown_throws() {
        assertThatThrownBy(() -> GcpScopeSupport.parseAuthMode("BANANAS", "ctx"))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("BANANAS");
    }

    @Test
    void scopeSupport_toAuthScope_buildsRecord() {
        GcpAuthScope s = GcpScopeSupport.toAuthScope("p", "global", "sa@x.iam");
        assertThat(s.projectId()).isEqualTo("p");
        assertThat(s.location()).isEqualTo("global");
        assertThat(s.impersonateServiceAccount()).isEqualTo("sa@x.iam");
    }

    @Test
    void scopeSupport_parseKvSecret_blank_returnsEmpty() {
        GcpAuthSecret r = GcpScopeSupport.parseKvSecret(om, null, "ctx");
        assertThat(r.serviceAccountJson()).isNull();
        assertThat(r.serviceAccountJsonBase64()).isNull();
        GcpAuthSecret r2 = GcpScopeSupport.parseKvSecret(om, "  ", "ctx");
        assertThat(r2.serviceAccountJson()).isNull();
    }

    @Test
    void scopeSupport_parseKvSecret_stringForm_passesThroughText() {
        String kv = "{\"serviceAccountKeyJson\":\"raw-sa-string\"}";
        GcpAuthSecret r = GcpScopeSupport.parseKvSecret(om, kv, "ctx");
        assertThat(r.serviceAccountJson()).isEqualTo("raw-sa-string");
    }

    @Test
    void scopeSupport_parseKvSecret_objectForm_serializesToJsonString() {
        String kv = "{\"serviceAccountKeyJson\":{\"type\":\"service_account\",\"project_id\":\"p\"}}";
        GcpAuthSecret r = GcpScopeSupport.parseKvSecret(om, kv, "ctx");
        assertThat(r.serviceAccountJson()).contains("service_account").contains("project_id");
    }

    @Test
    void scopeSupport_parseKvSecret_base64Only() {
        String kv = "{\"serviceAccountKeyJsonBase64\":\"dGVzdA==\"}";
        GcpAuthSecret r = GcpScopeSupport.parseKvSecret(om, kv, "ctx");
        assertThat(r.serviceAccountJsonBase64()).isEqualTo("dGVzdA==");
        assertThat(r.serviceAccountJson()).isNull();
    }

    @Test
    void scopeSupport_parseKvSecret_textualBlank_returnsNullField() {
        String kv = "{\"serviceAccountKeyJson\":\"\"}";
        GcpAuthSecret r = GcpScopeSupport.parseKvSecret(om, kv, "ctx");
        assertThat(r.serviceAccountJson()).isNull();
    }

    @Test
    void scopeSupport_parseKvSecret_unparseable_throws() {
        assertThatThrownBy(() -> GcpScopeSupport.parseKvSecret(om, "not-json", "ctx"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CREDENTIAL_INVALID");
    }

    @Test
    void scopeSupport_parseKvSecret_unsupportedNodeType_throws() {
        // serviceAccountKeyJson as a number — must throw DEPLOY_CREDENTIAL_INVALID.
        String kv = "{\"serviceAccountKeyJson\":123}";
        assertThatThrownBy(() -> GcpScopeSupport.parseKvSecret(om, kv, "ctx"))
                .isInstanceOf(PermanentAgentException.class)
                .hasFieldOrPropertyWithValue("errorCode", "DEPLOY_CREDENTIAL_INVALID");
    }
}
