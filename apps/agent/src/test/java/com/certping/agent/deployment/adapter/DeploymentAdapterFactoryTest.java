// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter;

import com.certping.agent.deployment.adapter.aws.AwsApiGatewayHttpDeploymentAdapter;
import com.certping.agent.deployment.adapter.aws.AwsApiGatewayRestDeploymentAdapter;
import com.certping.agent.deployment.adapter.aws.AwsCloudFrontDeploymentAdapter;
import com.certping.agent.deployment.adapter.aws.AwsDeploymentAdapter;
import com.certping.agent.deployment.adapter.aws.AwsElbDeploymentAdapter;
import com.certping.agent.deployment.adapter.akamai.AkamaiCpsDeploymentAdapter;
import com.certping.agent.deployment.adapter.azure.AzureAgcDeploymentAdapter;
import com.certping.agent.deployment.adapter.azure.AzureAppGatewayDeploymentAdapter;
import com.certping.agent.deployment.adapter.azure.AzureAfdDeploymentAdapter;
import com.certping.agent.deployment.adapter.azure.AzureDeploymentAdapter;
import com.certping.agent.deployment.adapter.cloudflare.CloudflareEdgeDeploymentAdapter;
import com.certping.agent.deployment.adapter.gcp.GcpAlbDeploymentAdapter;
import com.certping.agent.deployment.adapter.gcp.GcpCertificateManagerDeploymentAdapter;
import com.certping.agent.deployment.adapter.gcp.GcpProxyNlbDeploymentAdapter;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.deployment.adapter.kubernetes.KubernetesDeploymentAdapter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class DeploymentAdapterFactoryTest {

    @Mock private AzureDeploymentAdapter azureAdapter;
    @Mock private AwsDeploymentAdapter awsAdapter;
    @Mock private AzureAppGatewayDeploymentAdapter azureAppGatewayAdapter;
    @Mock private AzureAgcDeploymentAdapter azureAgcAdapter;
    @Mock private AzureAfdDeploymentAdapter azureAfdAdapter;
    @Mock private AwsElbDeploymentAdapter awsElbAdapter;
    @Mock private AwsApiGatewayRestDeploymentAdapter awsApiGatewayRestAdapter;
    @Mock private AwsApiGatewayHttpDeploymentAdapter awsApiGatewayHttpAdapter;
    @Mock private AwsCloudFrontDeploymentAdapter awsCloudFrontAdapter;
    @Mock private CloudflareEdgeDeploymentAdapter cloudflareAdapter;
    @Mock private AkamaiCpsDeploymentAdapter akamaiAdapter;
    @Mock private KubernetesDeploymentAdapter kubernetesAdapter;
    @Mock private GcpCertificateManagerDeploymentAdapter gcpCertificateManagerAdapter;
    @Mock private GcpAlbDeploymentAdapter gcpAlbAdapter;
    @Mock private GcpProxyNlbDeploymentAdapter gcpProxyNlbAdapter;

    private DeploymentAdapterFactory factory;

    @BeforeEach
    void setUp() {
        factory = new DeploymentAdapterFactory(List.of(azureAdapter, awsAdapter, azureAppGatewayAdapter,
            azureAgcAdapter, azureAfdAdapter, awsElbAdapter, awsApiGatewayRestAdapter, awsApiGatewayHttpAdapter,
            awsCloudFrontAdapter, cloudflareAdapter, akamaiAdapter, kubernetesAdapter,
            gcpCertificateManagerAdapter, gcpAlbAdapter, gcpProxyNlbAdapter));
    }

    @Test
    void create_azureKv_returnsAzureAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AZURE_KV);
        assertThat(adapter).isSameAs(azureAdapter);
    }

    @Test
    void create_awsAcm_returnsAwsAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_ACM);
        assertThat(adapter).isSameAs(awsAdapter);
    }

    @Test
    void create_kubernetesSecrets_returnsKubernetesAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.KUBERNETES_SECRETS);
        assertThat(adapter).isSameAs(kubernetesAdapter);
    }

    @Test
    void create_azureAppGw_returnsAzureAppGatewayAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AZURE_APP_GW);
        assertThat(adapter).isSameAs(azureAppGatewayAdapter);
    }

    @Test
    void create_azureAgc_returnsAzureAgcAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AZURE_APP_GW_CONTAINERS);
        assertThat(adapter).isSameAs(azureAgcAdapter);
    }

    @Test
    void create_azureAfd_returnsAzureAfdAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AZURE_AFD);
        assertThat(adapter).isSameAs(azureAfdAdapter);
    }

    @Test
    void create_awsAlb_returnsAwsElbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_ALB);
        assertThat(adapter).isSameAs(awsElbAdapter);
    }

    @Test
    void create_awsNlb_returnsAwsElbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_NLB);
        assertThat(adapter).isSameAs(awsElbAdapter);
    }

    @Test
    void create_awsApiGatewayRest_returnsAwsApiGatewayRestAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_API_GW_REST);
        assertThat(adapter).isSameAs(awsApiGatewayRestAdapter);
    }

    @Test
    void create_awsApiGatewayHttp_returnsAwsApiGatewayHttpAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_API_GW_HTTP);
        assertThat(adapter).isSameAs(awsApiGatewayHttpAdapter);
    }

    @Test
    void create_awsCloudFront_returnsAwsCloudFrontAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AWS_CLOUDFRONT);
        assertThat(adapter).isSameAs(awsCloudFrontAdapter);
    }

    @Test
    void create_cloudflareEdge_returnsCloudflareAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.CLOUDFLARE_EDGE);
        assertThat(adapter).isSameAs(cloudflareAdapter);
    }

    @Test
    void create_akamaiCps_returnsAkamaiAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.AKAMAI_CPS);
        assertThat(adapter).isSameAs(akamaiAdapter);
    }

    @Test
    void create_gcpCertManager_returnsGcpCertificateManagerAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.GCP_CERT_MANAGER);
        assertThat(adapter).isSameAs(gcpCertificateManagerAdapter);
    }

    @Test
    void create_gcpAlb_returnsGcpAlbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.GCP_ALB);
        assertThat(adapter).isSameAs(gcpAlbAdapter);
    }

    @Test
    void create_gcpApiGw_returnsGcpAlbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.GCP_API_GW);
        assertThat(adapter).isSameAs(gcpAlbAdapter);
    }

    @Test
    void create_gcpCloudCdn_returnsGcpAlbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.GCP_CLOUD_CDN);
        assertThat(adapter).isSameAs(gcpAlbAdapter);
    }

    @Test
    void create_gcpProxyNlb_returnsGcpProxyNlbAdapter() {
        DeploymentAdapter adapter = factory.create(TargetType.GCP_PROXY_NLB);
        assertThat(adapter).isSameAs(gcpProxyNlbAdapter);
    }

    @Test
    void create_null_throwsPermanentException() {
        assertThatThrownBy(() -> factory.create(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DEPLOY_UNKNOWN_TARGET"));
    }
}
