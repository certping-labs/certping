// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.aws;

import com.certping.agent.deployment.CertificateBundle;
import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RateLimitClassifier;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.acm.AcmClient;
import software.amazon.awssdk.services.acm.model.ImportCertificateRequest;
import software.amazon.awssdk.services.acm.model.ImportCertificateResponse;
import software.amazon.awssdk.services.acm.model.Tag;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Imports a cert into AWS ACM, idempotent on existing ARN. Not
 * concerned with auth — caller provides a fully-resolved {@link AwsCredentialsProvider}.
 */
@Component
@RequiredArgsConstructor
public class AwsAcmImportService {

    /** AWS error codes that mean the credentials themselves are bad — retrying can't help. */
    private static final Set<String> AWS_AUTH_ERROR_CODES = Set.of(
            "InvalidSignature", "InvalidSignatureException", "SignatureDoesNotMatch",
            "UnrecognizedClient", "UnrecognizedClientException", "InvalidClientTokenId",
            "InvalidAccessKeyId", "AuthFailure",
            "AccessDenied", "AccessDeniedException",
            "ExpiredToken", "ExpiredTokenException");

    /**
     * @param bundle           cert + key + chain
     * @param region           ACM region (must match wherever the cert will be referenced)
     * @param credentialsProvider built by {@link com.certping.agent.deployment.cloud.aws.AwsCloudCredentialResolver}
     * @param existingArn      null on first deploy; existing ARN re-uses the resource (idempotent update)
     * @param tags             only used on first deploy (tags are immutable on existing certs)
     */
    public String importCertificate(CertificateBundle bundle,
                                    String region,
                                    AwsCredentialsProvider credentialsProvider,
                                    String existingArn,
                                    List<Tag> tags) {
        try (AcmClient acmClient = AcmClient.builder()
                .region(Region.of(region))
                .credentialsProvider(credentialsProvider)
                .build()) {

            ImportCertificateRequest.Builder requestBuilder = ImportCertificateRequest.builder()
                    .certificate(SdkBytes.fromUtf8String(bundle.leafCertificate()))
                    .privateKey(SdkBytes.fromUtf8String(bundle.privateKey()));

            if (bundle.certChain() != null && !bundle.certChain().isBlank()) {
                requestBuilder.certificateChain(SdkBytes.fromUtf8String(bundle.certChain()));
            }
            if (existingArn != null && !existingArn.isBlank()) {
                requestBuilder.certificateArn(existingArn.trim());
            } else if (tags != null && !tags.isEmpty()) {
                requestBuilder.tags(tags);
            }

            ImportCertificateResponse resp = acmClient.importCertificate(requestBuilder.build());
            String arn = resp.certificateArn();
            if (arn == null || arn.isBlank()) {
                throw new PermanentAgentException("DEPLOY_RESULT_NULL_ARN",
                        "AWS ACM importCertificate returned null/empty certificate ARN");
            }
            return arn;

        } catch (SdkException e) {
            if (e instanceof AwsServiceException ase) {
                Optional<RateLimitClassifier.RateLimitVerdict> rl =
                        RateLimitClassifier.fromAws(ase, "DEPLOY_PROVIDER_THROTTLED");
                if (rl.isPresent()) {
                    String target = (existingArn != null && !existingArn.isBlank()) ? existingArn : "new-import";
                    throw rl.get().toRetryable("aws ACM import", target, e);
                }
            }
            Optional<RateLimitClassifier.RateLimitVerdict> rl =
                    RateLimitClassifier.classify(e, "DEPLOY_PROVIDER_THROTTLED");
            if (rl.isPresent()) {
                String target = (existingArn != null && !existingArn.isBlank()) ? existingArn : "new-import";
                throw rl.get().toRetryable("aws ACM import", target, e);
            }
            throw mapAcmImportException(e);
        }
    }

    /**
     * Maps an AWS SDK failure to the right exception bucket. Credential/signature errors and
     * malformed-cert rejections are PERMANENT (retrying can't help — the user must fix creds or
     * input); throttling, 5xx and transport errors stay TRANSIENT for scheduled retry.
     */
    static RuntimeException mapAcmImportException(SdkException e) {
        if (e instanceof AwsServiceException ase) {
            String code = ase.awsErrorDetails() != null ? ase.awsErrorDetails().errorCode() : "unknown";
            if ("ValidationException".equals(code) || "InvalidArnException".equals(code)) {
                return new PermanentAgentException("DEPLOY_CERT_FORMAT_INVALID",
                        "AWS ACM rejected certificate: " + code + " — " + e.getMessage(), e);
            }
            if (AWS_AUTH_ERROR_CODES.contains(code)) {
                return new PermanentAgentException("DEPLOY_AUTH_INVALID",
                        "AWS credentials rejected (" + code + ") — update them in Integrations: "
                                + e.getMessage(), e);
            }
            return new TransientAgentException("DEPLOY_ACM_ERROR",
                    "AWS ACM import failed (" + code + "): " + e.getMessage(), e);
        }
        return new TransientAgentException("DEPLOY_AWS_SDK_ERROR",
                "AWS SDK error during ACM import: " + e.getMessage(), e);
    }
}
