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
import software.amazon.awssdk.services.elasticloadbalancingv2.ElasticLoadBalancingV2Client;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.AddListenerCertificatesRequest;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.Certificate;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.ElasticLoadBalancingV2Exception;
import software.amazon.awssdk.services.elasticloadbalancingv2.model.RemoveListenerCertificatesRequest;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * AWS ALB/NLB deployment — one credential = one load balancer.
 *
 * <p>Scope: {@link AwsElbScope} — LB ARN and available listeners live here.
 * <br>Targets: {@link AwsElbTargets} — selects which listeners (subset of scope.listeners).
 * <br>Result: flat {@code {"arn": "<acm-arn>"}} — same as AWS_ACM.
 *
 * <p>The adapter imports the cert to ACM (reusing the prior ARN on rotation),
 * then attaches it to each selected listener via {@code AddListenerCertificates}.
 */
@Slf4j
@Component
@DeploymentAdapterFor({TargetType.AWS_ALB, TargetType.AWS_NLB})
@RequiredArgsConstructor
public class AwsElbDeploymentAdapter implements DeploymentAdapter {

    private static final String CTX = "AWS Load Balancer";

    private final SecretStore secretStore;
    private final AwsAcmImportService acmImportService;
    private final AwsCloudCredentialResolver awsCredentialResolver;
    private final ObjectMapper objectMapper;

    @Override
    public DeploymentResult deploy(CertificateBundle bundle, CertDeploymentMessage message) {
        AwsElbScope scope = parseScope(message.getCredentialScopeJson());
        AwsAuthMode authMode = AwsScopeSupport.parseAuthMode(scope.authMode(), CTX);
        validateScope(scope);

        AwsElbTargets targets = parseTargets(message.getTargetsJson());
        if (targets.listenerArns() == null || targets.listenerArns().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                    CTX + " requires non-empty targets.listenerArns");
        }

        // Validate selected listeners are a subset of scope.listeners
        Set<String> allowed = new LinkedHashSet<>(scope.listeners());
        for (String lis : targets.listenerArns()) {
            if (!allowed.contains(lis)) {
                throw new PermanentAgentException("DEPLOY_TARGETS_INVALID",
                        "listener '" + lis + "' is not in the credential's scope.listeners");
            }
        }

        AwsAuthSecret kv = readKvSecret(message);
        AwsAuthScope authScope = AwsScopeSupport.toAuthScope(
                scope.region(), scope.roleArn(), scope.externalId());
        AwsCredentialsProvider creds = awsCredentialResolver.resolve(authMode, authScope, kv, CTX);

        String domain = requireDomain(message.getDomain(), message.getCertificateXref());

        String existingArn = parsePriorArn(message.getConfigJson());
        boolean isFirstDeploy = existingArn == null || existingArn.isBlank();

        String arn = acmImportService.importCertificate(
                bundle, scope.region(), creds, existingArn,
                isFirstDeploy ? buildTags(domain, message) : List.of());

        try (ElasticLoadBalancingV2Client elb = ElasticLoadBalancingV2Client.builder()
                .region(Region.of(scope.region()))
                .credentialsProvider(creds)
                .build()) {

            for (String listenerArn : targets.listenerArns()) {
                log.info("{}: attaching cert to listener={}", CTX, listenerArn);
                elb.addListenerCertificates(AddListenerCertificatesRequest.builder()
                        .listenerArn(listenerArn)
                        .certificates(Certificate.builder().certificateArn(arn).build())
                        .build());

                if (!isFirstDeploy && existingArn != null && !existingArn.equals(arn)) {
                    elb.removeListenerCertificates(RemoveListenerCertificatesRequest.builder()
                            .listenerArn(listenerArn)
                            .certificates(Certificate.builder().certificateArn(existingArn).build())
                            .build());
                }
            }

        } catch (ElasticLoadBalancingV2Exception e) {
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.fromAws(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws ELB update",
                        String.join(",", targets.listenerArns()), e);
            }
            throw new TransientAgentException("DEPLOY_ELB_ERROR",
                    "ELBv2 listener update failed: " + e.getMessage(), e);
        } catch (SdkException e) {
            if (e instanceof AwsServiceException ase) {
                Optional<RateLimitClassifier.RateLimitVerdict> rlt =
                        RateLimitClassifier.fromAws(ase, "DEPLOY_PROVIDER_THROTTLED");
                if (rlt.isPresent()) {
                    throw rlt.get().toRetryable("aws ELB update",
                            String.join(",", targets.listenerArns()), e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                throw rl.get().toRetryable("aws ELB update",
                        String.join(",", targets.listenerArns()), e);
            }
            throw new TransientAgentException("DEPLOY_AWS_SDK_ERROR",
                    "AWS SDK error during ELB deployment: " + e.getMessage(), e);
        }

        // Flat result — just the ACM ARN, like AWS_ACM
        return DeploymentResult.of(arn, toResultJson(arn));
    }

    // ---------- parsing ----------

    void validateScope(AwsElbScope scope) {
        if (scope.region() == null || scope.region().isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.region is required");
        }
        if (scope.listeners() == null || scope.listeners().isEmpty()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " credentialScope.listeners must be a non-empty array");
        }
    }

    private AwsElbScope parseScope(String json) {
        if (json == null || json.isBlank()) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    CTX + " requires credentialScopeJson");
        }
        try {
            return objectMapper.readValue(json, AwsElbScope.class);
        } catch (Exception e) {
            throw new PermanentAgentException("DEPLOY_CREDENTIAL_INVALID",
                    "Failed to parse " + CTX + " credentialScopeJson: " + e.getMessage(), e);
        }
    }

    private AwsElbTargets parseTargets(String json) {
        if (json == null || json.isBlank()) {
            return new AwsElbTargets(List.of());
        }
        try {
            return objectMapper.readValue(json, AwsElbTargets.class);
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

    private String requireDomain(String rawDomain, String certXref) {
        String domain = CertificateIdentityUtils.normaliseDomain(rawDomain);
        if (domain.isBlank()) {
            throw new PermanentAgentException("DEPLOY_DOMAIN_REQUIRED",
                    "CERT_DEPLOYMENT message missing required domain for xref=" + certXref);
        }
        return domain;
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
        try {
            Map<String, Object> root = new LinkedHashMap<>();
            root.put("arn", arn);
            return objectMapper.writeValueAsString(root);
        } catch (Exception e) {
            return "{\"arn\":\"" + arn + "\"}";
        }
    }

    private List<Tag> buildTags(String domain, CertDeploymentMessage message) {
        String orgId = message.getOrganizationId() == null ? "" : message.getOrganizationId();
        if (!domain.isBlank()) {
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
