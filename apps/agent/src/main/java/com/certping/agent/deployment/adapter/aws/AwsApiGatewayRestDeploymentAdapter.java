// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.deployment.DeploymentResult;
import com.certping.agent.deployment.adapter.DeploymentAdapter;
import com.certping.agent.deployment.adapter.DeploymentAdapterFor;
import com.certping.agent.deployment.cloud.aws.AwsAuthMode;
import com.certping.agent.deployment.cloud.aws.AwsAuthScope;
import com.certping.agent.deployment.cloud.aws.AwsAuthSecret;
import com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver;
import com.certping.agent.deployment.util.CertificateIdentityUtils;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDeploymentMessage;
import com.certping.agent.secrets.SecretStore;
import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.acm.model.Tag;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.EndpointType;
import software.amazon.awssdk.services.apigateway.model.GetDomainNameRequest;
import software.amazon.awssdk.services.apigateway.model.GetDomainNameResponse;
import software.amazon.awssdk.services.apigateway.model.PatchOperation;
import software.amazon.awssdk.services.apigateway.model.UpdateDomainNameRequest;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * AWS API Gateway (REST) deployment — one credential = one set of custom domains.
 *
 * <p>Scope: {@link AwsApiGwScope} — available customDomains live here (no endpointType — auto-discovered).
 * <br>Targets: {@link AwsApiGwTargets} — selects which domains (subset of scope.customDomains).
 * <br>Result: flat {@code {"arn": "<acm-arn>"}} — same as AWS_ACM.
 *
 * <p>The adapter imports the cert to ACM (reusing the prior ARN on rotation),
 * then auto-discovers each domain's endpoint type via {@code getDomainName()}
 * and patches the correct cert field ({@code /regionalCertificateArn} or {@code /certificateArn}).
 */
@Slf4j
@Component
@DeploymentAdapterFor(TargetType.AWS_API_GW_REST)
@RequiredArgsConstructor
public class AwsApiGatewayRestDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "AWS API Gateway (REST)";

    private final SecretStore secretStore;
    private final AwsAcmImportService acmImportService;
    private final AwsCloudCredentialResolver awsCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AwsApiGwScope scope = parseScope(message.getCredentialScopeJson());
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AwsApiGwTargets targets = parseTargets(message.getTargetsJson());
        if (targets.domainNames() == null || targets.domainNames().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " requires non-empty targets.domainNames");
        }

        // Validate selected domains are a subset of scope.customDomains
        Set<String> allowed = new LinkedHashSet<>(scope.customDomains());
        for (String dom : targets.domainNames()) {
            if (!allowed.contains(dom)) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "domain '" + dom + "' is not in the credential's scope.customDomains");
            }
        }

        AwsAuthSecret kv = readKvSecret(message);
        AwsAuthScope authScope = AwsScopeSupport.toAuthScope(
                scope.region(), scope.roleArn(), scope.externalId());
        AwsCredentialsProvider creds = awsCredentialResolver.resolve(authMode, authScope, kv, CTX);

        String existingArn = parsePriorArn(message.getConfigJson());
        boolean isFirstDeploy = existingArn == null || existingArn.isBlank();
        String tagDomain = CertificateIdentityUtils.normaliseDomain(message.getDomain());

        String arn = acmImportService.importCertificate(
                bundle, scope.region(), creds, existingArn,
                isFirstDeploy ? buildTags(tagDomain, message) : List.of());

        try (ApiGatewayClient apigw = ApiGatewayClient.builder()
                .region(Region.of(scope.region()))
                .credentialsProvider(creds)
                .build()) {

            for (String domainName : targets.domainNames()) {
                // Auto-discover endpoint type — no need for user to specify it
                String certPath = discoverCertPath(apigw, domainName);

                List<PatchOperation> patchOps = List.of(
                        PatchOperation.builder().op("replace").path(certPath).value(arn).build());

                apigw.updateDomainName(UpdateDomainNameRequest.builder()
                        .domainName(domainName).patchOperations(patchOps).build());
                log.info("{} updated domain '{}' (certPath={})", CTX, domainName, certPath);
            }
        } catch (AwsServiceException e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws ApiGateway REST update",
                        String.join(",", targets.domainNames()), e);
            }
            throw mapAwsServiceException(e, "API Gateway domain update failed");
        } catch (SdkException e) {
            if (e instanceof AwsServiceException ase) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromAws(ase, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("aws ApiGateway REST update",
                            String.join(",", targets.domainNames()), e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws ApiGateway REST update",
                        String.join(",", targets.domainNames()), e);
            }
            throw new TransientAgentException("DEPLOY_APIGW_ERROR",
                    "API Gateway domain update failed: " + e.getMessage(), e);
        }

        // Flat result — just the ACM ARN, like AWS_ACM
        return DeploymentResult.of(arn, toResultJson(arn));
    }

    private static RuntimeException mapAwsServiceException(AwsServiceException e, String context) {
        int status = e.statusCode();
        String msg = context + ": " + e.getMessage();
        if (status == 401 || status == 403) {
            return new PermanentAgentException("DEPLOY_APIGW_ACCESS_DENIED", msg, e);
        }
        if (status >= 400 && status < 500 && status != 429) {
            return new PermanentAgentException("DEPLOY_APIGW_REQUEST_INVALID", msg, e);
        }
        return new TransientAgentException("DEPLOY_APIGW_ERROR", msg, e);
    }

    /**
     * Discovers the endpoint type for a custom domain by calling {@code getDomainName()}.
     *
     * <p>Returns the patch path: {@code /regionalCertificateArn} for REGIONAL,
     * {@code /certificateArn} for EDGE.
     */
    private String discoverCertPath(ApiGatewayClient apigw, String domainName) {
        try {
            GetDomainNameResponse resp = apigw.getDomainName(
                    GetDomainNameRequest.builder().domainName(domainName).build());

            if (resp.endpointConfiguration() != null
                    && resp.endpointConfiguration().types() != null
                    && !resp.endpointConfiguration().types().isEmpty()) {
                EndpointType type = resp.endpointConfiguration().types().get(0);
                if (type == EndpointType.EDGE) {
                    return "/certificateArn";
                }
            }
        } catch (SdkException e) {
            log.warn("{} getDomainName('{}') failed, defaulting to REGIONAL: {}",
                    CTX, domainName, e.getMessage());
        }
        return "/regionalCertificateArn";
    }

    void validateScope(AwsApiGwScope scope) {
        if (scope.region() == null || scope.region().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.region is required");
        }
        if (scope.customDomains() == null || scope.customDomains().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.customDomains must be a non-empty array");
        }
    }

    private AwsApiGwScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AwsApiGwScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AwsApiGwTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AwsApiGwTargets(List.of());
        }
        try {
            return objectMapper.readValue(json, AwsApiGwTargets.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    "Failed to parse " + CTX + " targetsJson: " + e.getMessage(), e);
        }
    }

    private AwsAuthSecret readKvSecret(CertDeploymentMessage message) {
        if (message.getDeploymentCredHandle() == null || message.getDeploymentCredHandle().isBlank()) {
            return AwsAuthSecret.empty();
        }
        return AwsScopeSupport.parseKvSecret(
                objectMapper, secretStore.read(message.getDeploymentCredHandle()), CTX);
    }

    private String parsePriorArn(String configJson) {
        if (configJson == null || configJson.isBlank()) return null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> map = objectMapper.readValue(configJson, Map.class);
            Object arn = map.get("arn");
            return arn == null ? null : arn.toString();
        } catch (Exception e) {
            log.warn("Failed to parse ARN from configJson='{}': {}", configJson, e.getMessage());
            return null;
        }
    }

    private String toResultJson(String arn) {
        return "{\"arn\":\"" + arn + "\"}";
    }

    private List<Tag> buildTags(String domain, CertDeploymentMessage message) {
        String orgId = message.getOrganizationId() == null ? "" : message.getOrganizationId();
        if (domain != null && !domain.isBlank()) {
            return List.of(
                    Tag.builder().key("ManagedBy").value("certping-agent").build(),
                    Tag.builder().key("OrganizationId").value(orgId).build(),
                    Tag.builder().key("Domain").value(domain).build());
        }
        return List.of(
                Tag.builder().key("ManagedBy").value("certping-agent").build(),
                Tag.builder().key("OrganizationId").value(orgId).build());
    }
}
