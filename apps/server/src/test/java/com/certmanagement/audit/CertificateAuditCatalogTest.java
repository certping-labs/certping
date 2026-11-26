// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.constants.FeatureFlags;
import com.certmanagement.constants.ResourceType;
import com.certmanagement.controller.CertExportController;
import com.certmanagement.controller.CertManagementController;
import com.certmanagement.util.UserFacingErrorMessages;
import org.junit.jupiter.api.Test;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The certificate and deployment events of the catalog: each is a customer event of its category with a feature
 * key the platform has (or none, for a core one), reads with any subject field missing, and every reason the
 * certificate flows record reads as a sentence of its own. Every change endpoint of the certificate controller
 * records its failures.
 */
class CertificateAuditCatalogTest {

    private static final Pattern VARIABLE = Pattern.compile("#([A-Za-z_][A-Za-z0-9_]*)");

    private static final List<AuditEventType> CERTIFICATE_EVENTS = Arrays.stream(AuditEventType.values())
            .filter(type -> type.category() == AuditCategory.CERTIFICATES || type.category() == AuditCategory.DEPLOYMENTS)
            .filter(type -> !type.key().startsWith("deployment_target."))
            .toList();

    /** The reasons the certificate and deployment flows record, other than an agent's own codes. */
    private static final List<String> FLOW_REASONS = List.of("SERVICE_UNAVAILABLE", "FEATURE_OFF",
            "DNS_CREDENTIAL_MISSING", "RENEWAL_TRIGGER_FAILED", "DEPLOYMENT_CREDENTIAL_INVALID",
            "DEPLOYMENT_CREDENTIAL_MISSING", "DEPLOYMENT_CONFIG_MISSING", "CERT_NOT_EXPORTABLE", "CERT_MATERIAL_GONE",
            "CERT_MATERIAL_MISMATCH", "EXPORT_RATE_LIMITED", "EXPORT_KEY_NOT_PERMITTED", "EXPORT_UNAVAILABLE",
            "NOT_FOUND", "PERMISSION_DENIED", "FEATURE_DISABLED", "INVALID_INPUT");

    /** Agent codes the brief names; their copy is UserFacingErrorMessages'. */
    private static final List<String> AGENT_REASONS = List.of("DEPLOY_AZURE_KV_IMPORT_FAILED",
            "DEPLOY_GCP_SSL_CERT_FAILED", "DEPLOY_CERT_REJECTED", "KV_URI_INVALID", "DNS_AUTH_FAILED",
            "ACME_RATE_LIMITED", "REVOCATION_UNAUTHORIZED");

    @Test
    void theCatalogHasEveryCertificateAndDeploymentEvent() {
        assertThat(CERTIFICATE_EVENTS).extracting(AuditEventType::key).contains(
                "certificate.issue_requested", "certificate.issued", "certificate.manual_issue_requested",
                "certificate.dns_validated", "certificate.renewal_requested", "certificate.auto_renewal_started",
                "certificate.renewed", "certificate.auto_renewal_skipped", "certificate.revoke_requested",
                "certificate.revoked", "certificate.deleted", "certificate.converted_to_automated",
                "certificate.exported", "certificate.expired", "deployment.requested", "deployment.succeeded",
                "deployment.failed", "deployment.auto_started", "deployment.auto_skipped");
    }

    @Test
    void eachIsACustomerEventOfItsCategoryWithARealFeatureKey() throws IllegalAccessException {
        Set<String> featureKeys = featureFlagConstants();
        assertThat(CERTIFICATE_EVENTS).allSatisfy(type -> {
            assertThat(type.visibility()).as(type.key()).isEqualTo(AuditVisibility.CUSTOMER);
            assertThat(type.featureKey() == null || featureKeys.contains(type.featureKey()))
                    .as("%s: %s is a FeatureFlags key or core", type.key(), type.featureKey()).isTrue();
            if (type.key().startsWith("deployment.")) {
                assertThat(type.category()).isEqualTo(AuditCategory.DEPLOYMENTS);
                assertThat(type.resourceType()).isEqualTo(ResourceType.DEPLOYMENT);
                assertThat(type.featureKey()).isEqualTo(FeatureFlags.CERTIFICATE_DEPLOYMENT);
            } else {
                assertThat(type.category()).isEqualTo(AuditCategory.CERTIFICATES);
                assertThat(type.resourceType()).isEqualTo(ResourceType.CERTIFICATE);
            }
            assertThat(type.summary(AuditSubject.NONE)).isNotBlank().doesNotContain("null").doesNotContain("  ");
            assertThat(type.failure(AuditSubject.NONE)).isNotBlank().doesNotContain("null").doesNotContain("  ");
        });
        assertThat(AuditEventType.CERTIFICATE_DELETED.isCore()).isTrue();
        assertThat(AuditEventType.CERTIFICATE_EXPIRED.isCore()).isTrue();
        assertThat(AuditEventType.CERTIFICATE_EXPORTED.isCore()).isTrue();
    }

    @Test
    void everyAgentResultNamesTheRequestingMemberByIdOnly() {
        assertThat(List.of(AuditEventType.CERTIFICATE_ISSUED, AuditEventType.CERTIFICATE_RENEWED,
                AuditEventType.CERTIFICATE_REVOKED, AuditEventType.DEPLOYMENT_SUCCEEDED,
                AuditEventType.DEPLOYMENT_FAILED)).allSatisfy(type ->
                assertThat(type.allowedAttributes()).as(type.key()).contains("requestedBy")
                        .doesNotContain("requestedByEmail", "email", "errorDetail", "error", "detail"));
        assertThat(CERTIFICATE_EVENTS).allSatisfy(type -> assertThat(type.allowedAttributes()).as(type.key())
                .noneMatch(name -> name.toLowerCase().contains("detail") || name.toLowerCase().contains("message")
                        || name.toLowerCase().contains("handle")));
    }

    @Test
    void everyReasonTheCertificateFlowsRecordReadsAsASentenceOfItsOwn() {
        String internalError = AuditReason.INTERNAL_ERROR.message(null);
        String fallback = UserFacingErrorMessages.forCode("NO_SUCH_REASON_CODE_FOR_TEST");
        Set<String> sentences = new HashSet<>();
        List<String> all = new ArrayList<>(FLOW_REASONS);
        all.addAll(AGENT_REASONS);
        assertThat(all).allSatisfy(code -> {
            AuditReason reason = AuditReason.of(code);
            assertThat(reason.code()).isEqualTo(code);
            String message = reason.message("req-123");
            assertThat(message).as(code).isNotBlank().isNotEqualTo(internalError).isNotEqualTo(fallback)
                    .doesNotContain(code).doesNotContain("req-123");
            if (FLOW_REASONS.contains(code)) {
                sentences.add(message);
            }
        });
        assertThat(sentences).as("each flow reason has copy of its own").hasSizeGreaterThanOrEqualTo(14);
    }

    @Test
    void aReasonIsTheAgentsCodeWithRetryGiveUpUnwrappedAndNeverItsText() {
        assertThat(AuditReason.fromAgent("RETRY_GIVE_UP", "DEPLOY_AZURE_KV_IMPORT_FAILED").code())
                .isEqualTo("DEPLOY_AZURE_KV_IMPORT_FAILED");
        assertThat(AuditReason.fromAgent("RETRY_GIVE_UP", null).code()).isEqualTo("RETRY_GIVE_UP");
        assertThat(AuditReason.fromAgent("KV_URI_INVALID", "ignored").code()).isEqualTo("KV_URI_INVALID");
        assertThat(AuditReason.fromAgent("RETRY_GIVE_UP", "example-vault-prod.vault.azure.net refused: 403"))
                .isEqualTo(AuditReason.INTERNAL_ERROR);
        assertThat(AuditReason.fromAgent("jdbc:postgresql://db01.internal:5432/certping", null))
                .isEqualTo(AuditReason.INTERNAL_ERROR);
    }

    /** Change endpoints of the certificate controllers recorded elsewhere than through @AuditFailure. */
    private static final Map<Class<?>, Set<String>> RECORDED_ELSEWHERE = Map.of(
            // Every refusal but a 400 is a durable row from CertExportAuditRecorder: certificate.exported, or
            // access.certificate_export_refused when no certificate was resolved.
            CertExportController.class, Set.of("export"));

    @Test
    void everyCertificateChangeEndpointRecordsItsFailures() {
        List<String> missing = new ArrayList<>();
        for (Class<?> controller : List.of(CertManagementController.class, CertExportController.class)) {
            for (Method method : controller.getDeclaredMethods()) {
                if (isChange(method) && !RECORDED_ELSEWHERE.getOrDefault(controller, Set.of()).contains(method.getName())
                        && AnnotatedElementUtils.findMergedAnnotation(method, AuditFailure.class) == null) {
                    missing.add(controller.getSimpleName() + "." + method.getName());
                }
            }
        }
        assertThat(missing).as("change endpoints without @AuditFailure").isEmpty();
    }

    @Test
    void everyExpressionParsesAndReadsTheMethodsOwnParameters() {
        SpelExpressionParser parser = new SpelExpressionParser();
        DefaultParameterNameDiscoverer names = new DefaultParameterNameDiscoverer();
        int annotated = 0;
        for (Method method : CertManagementController.class.getDeclaredMethods()) {
            AuditFailure failure = method.getAnnotation(AuditFailure.class);
            if (failure == null) {
                continue;
            }
            annotated++;
            assertThat(CERTIFICATE_EVENTS).contains(failure.value());
            List<String> parameters = Arrays.asList(names.getParameterNames(method));
            for (String expression : List.of(failure.target(), failure.name(), failure.organization())) {
                if (expression.isBlank()) {
                    continue;
                }
                parser.parseExpression(expression);
                Matcher variable = VARIABLE.matcher(expression);
                while (variable.find()) {
                    assertThat(parameters).as("%s: %s", method.getName(), expression).contains(variable.group(1));
                }
            }
        }
        assertThat(annotated).isEqualTo(9);
    }

    private static boolean isChange(Method method) {
        return AnnotatedElementUtils.hasAnnotation(method, PostMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, PutMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, PatchMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, DeleteMapping.class);
    }

    private static Set<String> featureFlagConstants() throws IllegalAccessException {
        Set<String> keys = new HashSet<>();
        for (Field field : FeatureFlags.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class) {
                field.setAccessible(true);
                keys.add((String) field.get(null));
            }
        }
        return keys;
    }
}
