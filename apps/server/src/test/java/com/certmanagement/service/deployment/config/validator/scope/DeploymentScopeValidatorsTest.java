// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.deployment.config.validator.scope;

import com.certmanagement.exception.BadRequestException;
import com.certmanagement.service.deployment.config.DeploymentScopeValidator;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * One happy-path + one failure-path test per scope validator. Failure paths exercise the
 * field most likely to be missing in real misuses (auth mode, primary identifier, or array).
 */
class DeploymentScopeValidatorsTest {

    private final ObjectMapper objectMapper = JsonMapper.builderWithJackson2Defaults().build();

    private JsonNode read(String json) throws Exception {
        return objectMapper.readTree(json);
    }

    private void ok(DeploymentScopeValidator v, String json) throws Exception {
        assertThatCode(() -> v.validate(read(json))).doesNotThrowAnyException();
    }

    private void bad(DeploymentScopeValidator v, String json, String messagePart) throws Exception {
        assertThatThrownBy(() -> v.validate(read(json)))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining(messagePart);
    }

    // ─────────────────────────── AWS ───────────────────────────

    @Test void awsOrganization_happy_withOptionalLists() throws Exception {
        ok(new AwsOrganizationScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\",\"memberRoleName\":\"CertPingDiscoveryReadOnly\","
                        + "\"accountIds\":[\"111111111111\"],\"regions\":[\"eu-west-1\"]}");
    }

    @Test void awsOrganization_rejectsBadAccountId() throws Exception {
        bad(new AwsOrganizationScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\",\"accountIds\":[\"123\"]}",
                "accountIds");
    }

    @Test void awsOrganization_assumeRoleNeedsRoleArn() throws Exception {
        bad(new AwsOrganizationScopeValidator(),
                "{\"authMode\":\"ASSUME_ROLE\",\"region\":\"us-east-1\"}", "roleArn");
    }

    @Test void awsAcm_happy_assumeRole() throws Exception {
        ok(new AwsAcmScopeValidator(),
                "{\"authMode\":\"ASSUME_ROLE\",\"region\":\"us-east-1\",\"roleArn\":\"arn:aws:iam::1:role/r\"}");
    }

    @Test void awsAcm_assumeRole_missingRoleArn() throws Exception {
        bad(new AwsAcmScopeValidator(),
                "{\"authMode\":\"ASSUME_ROLE\",\"region\":\"us-east-1\"}", "roleArn");
    }

    @Test void awsAcm_invalidAuthMode() throws Exception {
        bad(new AwsAcmScopeValidator(),
                "{\"authMode\":\"NONSENSE\",\"region\":\"us-east-1\"}", "authMode");
    }

    @Test void awsElb_happy() throws Exception {
        ok(new AwsElbScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"," +
                "\"loadBalancerArn\":\"arn:aws:elb:...\"," +
                "\"listeners\":[\"arn:aws:elb:...:listener/1\",\"arn:aws:elb:...:listener/2\"]}");
    }

    @Test void awsElb_emptyListeners() throws Exception {
        bad(new AwsElbScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"," +
                "\"loadBalancerArn\":\"arn:aws:elb:...\",\"listeners\":[]}", "listeners");
    }

    @Test void awsApiGw_happy() throws Exception {
        ok(new AwsApiGatewayScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"," +
                "\"customDomains\":[\"api.example.com\"]}");
    }

    @Test void awsApiGw_missingCustomDomains() throws Exception {
        bad(new AwsApiGatewayScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"region\":\"us-east-1\"}", "customDomains");
    }

    @Test void awsCloudFront_happy() throws Exception {
        ok(new AwsCloudFrontScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\",\"distributionId\":\"E1\"}");
    }

    @Test void awsCloudFront_missingDistributionId() throws Exception {
        bad(new AwsCloudFrontScopeValidator(),
                "{\"authMode\":\"INSTANCE_PROFILE\"}", "distributionId");
    }

    // ─────────────────────────── Azure ───────────────────────────

    @Test void azureKv_happy() throws Exception {
        ok(new AzureKvScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"vaultUri\":\"https://kv.vault.azure.net/\"}");
    }

    @Test void azureKv_missingVaultUri() throws Exception {
        bad(new AzureKvScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\"}", "vaultUri");
    }

    @Test void azureAppGw_happy() throws Exception {
        ok(new AzureAppGatewayScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"appGateway\":\"agw\",\"listeners\":[\"l1\"]," +
                "\"sslCertName\":\"cert\",\"keyVaultUri\":\"https://kv/\"}");
    }

    @Test void azureAppGw_missingListeners() throws Exception {
        bad(new AzureAppGatewayScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"appGateway\":\"agw\"," +
                "\"sslCertName\":\"cert\",\"keyVaultUri\":\"https://kv/\"}", "listeners");
    }

    @Test void azureAfd_happy() throws Exception {
        ok(new AzureAfdScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"profileName\":\"afd\",\"keyVaultUri\":\"https://kv/\"," +
                "\"customDomains\":[\"d1\"]}");
    }

    @Test void azureAfd_missingCustomDomains() throws Exception {
        bad(new AzureAfdScopeValidator(),
                "{\"authMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"profileName\":\"afd\",\"keyVaultUri\":\"https://kv/\"}",
                "customDomains");
    }

    @Test void azureAgc_happy_azureAuth() throws Exception {
        ok(new AzureAgcScopeValidator(),
                "{\"azureAuthMode\":\"SERVICE_PRINCIPAL\",\"tenantId\":\"t\",\"subscriptionId\":\"s\"," +
                "\"resourceGroup\":\"rg\",\"clusterAuthMode\":\"AZURE\",\"clusterName\":\"aks\"," +
                "\"agcNamespace\":\"ns\",\"gatewayName\":\"gw\",\"secretNamespaces\":[\"app\"]}");
    }

    @Test void azureAgc_happy_inClusterSkipsAzureAuth() throws Exception {
        ok(new AzureAgcScopeValidator(),
                "{\"clusterAuthMode\":\"SA_INCLUSTER\",\"clusterName\":\"aks\"," +
                "\"agcNamespace\":\"ns\",\"gatewayName\":\"gw\",\"secretNamespaces\":[\"app\"]}");
    }

    @Test void azureAgc_missingSecretNamespaces() throws Exception {
        bad(new AzureAgcScopeValidator(),
                "{\"clusterAuthMode\":\"SA_INCLUSTER\",\"clusterName\":\"aks\"," +
                "\"agcNamespace\":\"ns\",\"gatewayName\":\"gw\"}", "secretNamespaces");
    }

    // ─────────────────────────── GCP ───────────────────────────

    @Test void gcpCertManager_happy_withMap() throws Exception {
        ok(new GcpCertManagerScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"," +
                "\"certificateMap\":\"map\"}");
    }

    @Test void gcpCertManager_happy_withoutMap() throws Exception {
        ok(new GcpCertManagerScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"}");
    }

    @Test void gcpCertManager_impersonateRequiresField() throws Exception {
        bad(new GcpCertManagerScopeValidator(),
                "{\"authMode\":\"IMPERSONATE_SERVICE_ACCOUNT\",\"projectId\":\"p\",\"location\":\"global\"," +
                "\"certificateMap\":\"map\"}",
                "impersonateServiceAccount");
    }

    @Test void gcpProxy_happy() throws Exception {
        ok(new GcpProxyScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"," +
                "\"targetProxy\":\"https-proxy-1\"}");
    }

    @Test void gcpProxy_missingTargetProxy() throws Exception {
        bad(new GcpProxyScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"}",
                "targetProxy");
    }

    @Test void gcpProxyNlb_happy() throws Exception {
        ok(new GcpProxyNlbScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"," +
                "\"targetSslProxy\":\"ssl-proxy-1\"}");
    }

    @Test void gcpProxyNlb_missingTargetSslProxy() throws Exception {
        bad(new GcpProxyNlbScopeValidator(),
                "{\"authMode\":\"WORKLOAD_IDENTITY\",\"projectId\":\"p\",\"location\":\"global\"}",
                "targetSslProxy");
    }

    // ─────────────────────────── Cloudflare / Akamai / F5 ───────────────────────────

    @Test void cloudflare_happy() throws Exception {
        ok(new CloudflareScopeValidator(),
                "{\"authMode\":\"API_TOKEN\",\"zoneId\":\"abc\",\"bundleMethod\":\"ubiquitous\"}");
    }

    @Test void cloudflare_invalidBundleMethod() throws Exception {
        bad(new CloudflareScopeValidator(),
                "{\"authMode\":\"API_TOKEN\",\"zoneId\":\"abc\",\"bundleMethod\":\"weird\"}",
                "bundleMethod");
    }

    @Test void cloudflare_missingZoneId() throws Exception {
        bad(new CloudflareScopeValidator(),
                "{\"authMode\":\"API_TOKEN\"}", "zoneId");
    }

    @Test void akamai_happy() throws Exception {
        ok(new AkamaiScopeValidator(),
                "{\"host\":\"akab.luna.akamaiapis.net\",\"enrollmentId\":\"12345\"}");
    }

    @Test void akamai_missingHost() throws Exception {
        bad(new AkamaiScopeValidator(),
                "{\"enrollmentId\":\"12345\"}", "host");
    }

    @Test void akamai_missingEnrollmentId() throws Exception {
        bad(new AkamaiScopeValidator(), "{\"host\":\"h\"}", "enrollmentId");
    }

    @Test void f5_happy() throws Exception {
        ok(new F5ScopeValidator(),
                "{\"authMode\":\"BASIC_AUTH\",\"bigipHost\":\"bigip.corp.local\",\"partition\":\"Common\"}");
    }

    @Test void f5_missingPartition() throws Exception {
        bad(new F5ScopeValidator(),
                "{\"authMode\":\"BASIC_AUTH\",\"bigipHost\":\"bigip.corp.local\"}", "partition");
    }

    @Test void f5_portOutOfRange() throws Exception {
        bad(new F5ScopeValidator(),
                "{\"authMode\":\"BASIC_AUTH\",\"bigipHost\":\"h\",\"partition\":\"Common\",\"bigipPort\":99999}",
                "bigipPort");
    }

    @Test void f5_emptyClientSslProfilesArrayRejected() throws Exception {
        bad(new F5ScopeValidator(),
                "{\"authMode\":\"BASIC_AUTH\",\"bigipHost\":\"h\",\"partition\":\"Common\",\"clientSslProfiles\":[]}",
                "clientSslProfiles");
    }

    // ─────────────────────────── Common: not-an-object input ───────────────────────────

    @Test void rejectsNonObjectInput() throws Exception {
        bad(new AwsAcmScopeValidator(), "[]", "JSON object");
    }
}
