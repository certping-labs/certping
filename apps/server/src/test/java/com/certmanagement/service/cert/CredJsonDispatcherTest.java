// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.exception.CredentialRejectedException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CredJsonDispatcherTest {

    private static final ObjectMapper TIME_AWARE = JsonMapper.builderWithJackson2Defaults().findAndAddModules().build();

    private final ObjectMapper mapper = new tools.jackson.databind.json.JsonMapper();
    private final CredJsonDispatcher dispatcher = new CredJsonDispatcher(mapper);

    private static final String CLUSTER_CA_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIBdzCCAR2gAwIBAgIUHD1zDyA3fBa//B4bM9DEPyPlKNYwCgYIKoZIzj0EAwIw
            ETEPMA0GA1UEAwwGazNzLWNhMB4XDTI2MTEwNTE2NTQ1N1oXDTM2MTEwMjE2NTQ1
            N1owETEPMA0GA1UEAwwGazNzLWNhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
            /QpQ8UMyDhvxEMx5vL/5hQKWLsplVgnVUs8ByxBm8VY28mt749zA38kAJJe7LdB8
            RGdgDqZYqL1vtudxaBzLq6NTMFEwHQYDVR0OBBYEFNn+yu31J0PDXQhkZ6J55bi3
            RKhAMB8GA1UdIwQYMBaAFNn+yu31J0PDXQhkZ6J55bi3RKhAMA8GA1UdEwEB/wQF
            MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgVxxnJBiJtQiwyA1F0RU8eOgXQlh4n7Mu
            T+edcjgvluMCIQDIUD7TLqarXPkvfKBxkQFatUgsfeGTxQzvz4bX+LzSYA==
            -----END CERTIFICATE-----
            """;

    @Test
    void serializeForKv_awsRoute53Dns_returnsJsonWithBothFields() throws Exception {
        JsonNode payload = mapper.readTree("{\"accessKeyId\":\"AKIA1\",\"secretAccessKey\":\"sk-1\"}");

        String kvValue = dispatcher.serializeForKv("AWS_ROUTE53", "DNS", payload);

        assertThat(mapper.readTree(kvValue))
                .isEqualTo(mapper.readTree("{\"accessKeyId\":\"AKIA1\",\"secretAccessKey\":\"sk-1\"}"));
    }

    @Test
    void serializeForKv_digiCertCa_keepsOnlyTheApiKey() throws Exception {
        String kvValue = dispatcher.serializeForKv("DIGICERT", "CA", mapper.readTree("{\"apiKey\":\"dc-1\",\"x\":2}"));

        assertThat(mapper.readTree(kvValue)).isEqualTo(mapper.readTree("{\"apiKey\":\"dc-1\"}"));
        assertThat(dispatcher.supports("DIGICERT", "CA")).isTrue();
        assertThat(dispatcher.supports("GLOBALSIGN", "CA")).isFalse();
    }

    @Test
    void serializeForKv_cloudflareDns_returnsJsonForConsistency() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiToken\":\"cf-token-xyz\"}");

        String kvValue = dispatcher.serializeForKv("CLOUDFLARE", "DNS", payload);

        // Consistent with other DNS providers — agent's DnsProviderFactory parses JSON for new writes
        // and falls back to bare-token for older secrets.
        assertThat(mapper.readTree(kvValue))
                .isEqualTo(mapper.readTree("{\"apiToken\":\"cf-token-xyz\"}"));
    }

    @Test
    void serializeForKv_namecheapDns_returnsJsonWithXmlApiFields() throws Exception {
        JsonNode payload = mapper.readTree("""
                {
                  "apiUser": "certping",
                  "username": "certping",
                  "apiKey": "nc-key",
                  "clientIp": "strip-me-too",
                  "ignored": "strip-me"
                }
                """);

        String kvValue = dispatcher.serializeForKv("NAMECHEAP", "DNS", payload);

        assertThat(mapper.readTree(kvValue))
                .isEqualTo(mapper.readTree("""
                        {
                          "apiUser": "certping",
                          "username": "certping",
                          "apiKey": "nc-key"
                        }
                        """));
    }

    @Test
    void serializeForKv_namecheapDns_rejectsMissingRequiredMetadata() throws Exception {
        JsonNode payload = mapper.readTree(
                "{\"apiUser\":\"certping\",\"username\":\" \",\"apiKey\":\"nc-key\"}");

        assertThatThrownBy(() -> dispatcher.serializeForKv("NAMECHEAP", "DNS", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Namecheap username is required");
    }

    @Test
    void serializeForKv_namecheapDns_rejectsMissingApiKey() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiUser\":\"certping\",\"username\":\"certping\"}");

        assertThatThrownBy(() -> dispatcher.serializeForKv("NAMECHEAP", "DNS", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Namecheap API key is required");
    }

    @Test
    void serializeForKv_hostingerDns_returnsJsonWithApiToken() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiToken\":\"hg-token-abc\"}");

        String kvValue = dispatcher.serializeForKv("HOSTINGER", "DNS", payload);

        assertThat(mapper.readTree(kvValue))
                .isEqualTo(mapper.readTree("{\"apiToken\":\"hg-token-abc\"}"));
    }

    @Test
    void serializeForKv_hostingerDns_stripsUnknownFields() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiToken\":\"hg-1\",\"injected\":\"evil\"}");

        String kvValue = dispatcher.serializeForKv("HOSTINGER", "DNS", payload);

        assertThat(kvValue).doesNotContain("injected");
        assertThat(kvValue).contains("hg-1");
    }

    @Test
    void serializeForKv_certPingDns_keepsOnlyTheToken() throws Exception {
        JsonNode payload = mapper.readTree(
                "{\"apiKey\":\"cpk_live_abc\",\"apiUrl\":\"https://dns-api.certping.com/api/v1/domains/token-api\",\"injected\":\"evil\"}");

        String kvValue = dispatcher.serializeForKv("CERTPING", "DNS", payload);

        assertThat(mapper.readTree(kvValue)).isEqualTo(mapper.readTree("{\"apiKey\":\"cpk_live_abc\"}"));
    }

    @Test
    void serializeForKv_powerDnsIsNoLongerADnsProvider() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiKey\":\"cpk_live_abc\"}");

        assertThatThrownBy(() -> dispatcher.serializeForKv("POWERDNS", "DNS", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("No credJson DTO mirror for DNS provider");
        assertThat(dispatcher.supports("POWERDNS", "DNS")).isFalse();
    }

    @Test
    void serializeForKv_certPingDns_rejectsAMissingToken() throws Exception {
        JsonNode payload = mapper.readTree("{\"apiKey\":\" \"}");

        assertThatThrownBy(() -> dispatcher.serializeForKv("CERTPING", "DNS", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("CertPing DNS API key is required");
    }

    @Test
    void serializeCertPingKeyConfig_keepsTheKeyDetailsWithTheExpiryAsAnIsoString() throws Exception {
        CredJsonDispatcher timeAware = new CredJsonDispatcher(TIME_AWARE);
        JsonNode details = TIME_AWARE.readTree("""
                {"tokenId":41,"tokenPrefix":"cpk_live_ab12cd34","expiresAt":"2027-10-21T08:00:00Z","apiKey":"cpk_live_secret"}
                """);

        String config = timeAware.serializeCertPingKeyConfig(details);

        assertThat(TIME_AWARE.readTree(config)).isEqualTo(TIME_AWARE.readTree(
                "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":0,\"tokenPrefix\":\"cpk_live_ab12cd34\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_test_ab12cd34\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34e\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd3\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd3!\",\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"expiresAt\":\"2027-10-21T08:00:00Z\"}",
            "{\"tokenId\":41,\"tokenPrefix\":\"cpk_live_ab12cd34\"}"})
    void serializeCertPingKeyConfig_refusesIncompleteDetails(String details) throws Exception {
        CredJsonDispatcher timeAware = new CredJsonDispatcher(TIME_AWARE);
        JsonNode payload = TIME_AWARE.readTree(details);

        assertThatThrownBy(() -> timeAware.serializeCertPingKeyConfig(payload))
                .isInstanceOf(CredentialRejectedException.class)
                .extracting("code").isEqualTo(CredentialRejectedException.DETAILS_INVALID);
    }

    @Test
    void serializeCertPingKeyConfig_requiresTheDetails() {
        assertThatThrownBy(() -> dispatcher.serializeCertPingKeyConfig(null))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("The CertPing DNS key's details are required.");
    }

    @Test
    void serializeForKv_stripsUnknownFields() throws Exception {
        JsonNode payload = mapper.readTree(
                "{\"accessKeyId\":\"AKIA2\",\"secretAccessKey\":\"sk-2\",\"injected\":\"evil\"}");

        String kvValue = dispatcher.serializeForKv("AWS_ROUTE53", "DNS", payload);

        // Unknown 'injected' field stripped by the DTO's @JsonIgnoreProperties — only typed fields survive.
        assertThat(kvValue).doesNotContain("injected");
        assertThat(kvValue).contains("AKIA2").contains("sk-2");
    }

    @Test
    void serializeForKv_awsDeploymentFamily_routesToAwsDtoForEveryAwsTargetType() throws Exception {
        JsonNode payload = mapper.readTree("{\"accessKeyId\":\"k\",\"secretAccessKey\":\"s\"}");
        for (String provider : new String[]{"AWS_ACM", "AWS_ALB", "AWS_NLB",
                "AWS_API_GW_REST", "AWS_API_GW_HTTP", "AWS_CLOUDFRONT"}) {
            String kvValue = dispatcher.serializeForKv(provider, "DEPLOYMENT", payload);
            assertThat(mapper.readTree(kvValue).get("accessKeyId").asString()).isEqualTo("k");
        }
    }

    @Test
    void serializeForKv_kubernetesDeployment_acceptsKubernetesDtoFields() throws Exception {
        JsonNode payload = mapper.createObjectNode()
                .put("apiServer", "https://k8s").put("bearerToken", "tok").put("awsRegion", "us-east-1")
                .put("caCertPem", CLUSTER_CA_PEM);

        String kvValue = dispatcher.serializeForKv("KUBERNETES_SECRETS", "DEPLOYMENT", payload);

        assertThat(mapper.readTree(kvValue).get("apiServer").asString()).isEqualTo("https://k8s");
        assertThat(mapper.readTree(kvValue).get("bearerToken").asString()).isEqualTo("tok");
    }

    @Test
    void serializeForKv_kubernetesServiceAccountToken_acceptsTheKubeconfigBase64Ca() {
        String base64 = Base64.getEncoder().encodeToString(CLUSTER_CA_PEM.getBytes(StandardCharsets.UTF_8));
        JsonNode payload = mapper.createObjectNode()
                .put("apiServer", "https://k8s").put("bearerToken", "tok").put("caCertBase64", base64);

        assertThat(dispatcher.serializeForKv("KUBERNETES_SECRETS", "DEPLOYMENT", payload)).contains(base64);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "{\"apiServer\":\"https://k8s\",\"bearerToken\":\"tok\"}",
            "{\"apiServer\":\"https://k8s\",\"bearerToken\":\"tok\",\"caCertPem\":\"  \"}",
            "{\"apiServer\":\"https://k8s\",\"serviceAccountToken\":\"tok\",\"caCertBase64\":\"\"}"})
    void serializeForKv_kubernetesServiceAccountToken_requiresTheClusterCa(String json) throws Exception {
        JsonNode payload = mapper.readTree(json);

        assertThatThrownBy(() -> dispatcher.serializeForKv("KUBERNETES_SECRETS", "DEPLOYMENT", payload))
                .isInstanceOf(CredentialRejectedException.class)
                .hasMessageContaining("cluster CA certificate is required");
    }

    @ParameterizedTest
    @ValueSource(strings = {"caCertPem", "caCertBase64"})
    void serializeForKv_kubernetesServiceAccountToken_rejectsACaThatIsNotACertificate(String field) {
        JsonNode payload = mapper.createObjectNode()
                .put("apiServer", "https://k8s").put("bearerToken", "tok").put(field, "bm90IGEgY2VydA==");

        assertThatThrownBy(() -> dispatcher.serializeForKv("KUBERNETES_SECRETS", "DEPLOYMENT", payload))
                .isInstanceOf(CredentialRejectedException.class)
                .hasMessageContaining("must be a PEM certificate");
    }

    @Test
    void serializeForKv_kubernetesCloudAuth_needsNoClusterCa() throws Exception {
        JsonNode payload = mapper.readTree("{\"awsRegion\":\"us-east-1\"}");

        assertThat(dispatcher.serializeForKv("KUBERNETES_SECRETS", "DEPLOYMENT", payload)).contains("us-east-1");
    }

    @Test
    void serializeForKv_unknownDnsProvider_rejects() throws Exception {
        JsonNode payload = mapper.readTree("{\"x\":1}");
        assertThatThrownBy(() -> dispatcher.serializeForKv("MYSTERY_DNS", "DNS", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("No credJson DTO mirror");
    }

    @Test
    void serializeForKv_unknownDeploymentProvider_rejects() throws Exception {
        JsonNode payload = mapper.readTree("{\"x\":1}");
        assertThatThrownBy(() -> dispatcher.serializeForKv("MYSTERY_TARGET", "DEPLOYMENT", payload))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("No credJson DTO mirror");
    }

    @Test
    void serializeForKv_nullCredJson_rejects() {
        assertThatThrownBy(() -> dispatcher.serializeForKv("AWS_ROUTE53", "DNS", null))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("required");
    }

    @Test
    void supports_returnsTrueForKnownProviders() {
        assertThat(dispatcher.supports("CLOUDFLARE", "DNS")).isTrue();
        assertThat(dispatcher.supports("NAMECHEAP", "DNS")).isTrue();
        assertThat(dispatcher.supports("HOSTINGER", "DNS")).isTrue();
        assertThat(dispatcher.supports("CERTPING", "DNS")).isTrue();
        assertThat(dispatcher.supports("AWS_ALB", "DEPLOYMENT")).isTrue();
        assertThat(dispatcher.supports("F5_BIGIP", "DEPLOYMENT")).isTrue();
    }

    @Test
    void supports_returnsFalseForUnknownProvider() {
        assertThat(dispatcher.supports("MYSTERY", "DNS")).isFalse();
    }
}
