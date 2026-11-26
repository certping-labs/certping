// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sensitive-read allow-list (the Access view): exactly these reads are recorded, each is a GET whose event is
 * an access event, and each expression parses and reads only the method's own parameters. A new
 * {@code @AuditedRead}, or one removed, fails here, so the list is changed on purpose.
 *
 * <p>Considered and left out, because what they return is not secret: an IoT certificate (its detail is the
 * public certificate's metadata, and there is no download of key material) and an SSO configuration's detail
 * (it says whether a client secret and an IdP certificate are set, never their values).
 *
 * <p>One access event is not an annotated read: {@code access.certificate_export_refused}, a certificate download
 * refused before any certificate was resolved, written durably by {@code CertExportAuditRecorder}.
 */
class AuditedReadCoverageTest {

    private static final Pattern VARIABLE = Pattern.compile("#([A-Za-z_][A-Za-z0-9_]*)");

    private static final Map<String, AuditEventType> ALLOW_LIST = Map.of(
            "CbomController.downloadCbom", AuditEventType.ACCESS_CBOM_DOWNLOADED,
            "AuditController.queryAuditLogs", AuditEventType.ACCESS_AUDIT_LOG_VIEWED,
            "AuditController.queryAccessLogs", AuditEventType.ACCESS_AUDIT_LOG_VIEWED);

    @Test
    void exactlyTheAllowListedReadsAreRecorded() throws Exception {
        Map<String, AuditEventType> annotated = new TreeMap<>();
        SpelExpressionParser parser = new SpelExpressionParser();
        DefaultParameterNameDiscoverer names = new DefaultParameterNameDiscoverer();
        for (Class<?> controller : controllers()) {
            for (Method method : controller.getDeclaredMethods()) {
                AuditedRead read = method.getAnnotation(AuditedRead.class);
                if (read == null) {
                    continue;
                }
                String where = controller.getSimpleName() + "." + method.getName();
                annotated.put(where, read.value());
                assertThat(AnnotatedElementUtils.hasAnnotation(method, GetMapping.class)).as(where).isTrue();
                assertThat(read.value().category()).as(where).isEqualTo(AuditCategory.ACCESS);
                List<String> parameters = Arrays.asList(names.getParameterNames(method));
                for (String expression : List.of(read.target(), read.organization())) {
                    if (expression.isBlank()) {
                        continue;
                    }
                    parser.parseExpression(expression);
                    Matcher variable = VARIABLE.matcher(expression);
                    while (variable.find()) {
                        assertThat(parameters).as("%s: %s", where, expression).contains(variable.group(1));
                    }
                }
            }
        }
        assertThat(annotated).isEqualTo(new TreeMap<>(ALLOW_LIST));
    }

    @Test
    void everyAccessEventIsOnTheAllowListOrTheExportRefusal() {
        List<AuditEventType> expected = new java.util.ArrayList<>(new java.util.HashSet<>(ALLOW_LIST.values()));
        expected.add(AuditEventType.ACCESS_CERTIFICATE_EXPORT_REFUSED);
        // No longer written (its endpoint is gone); kept so rows already in the trail still render.
        expected.add(AuditEventType.ACCESS_AGENT_CONNECTION_VIEWED);
        assertThat(Arrays.stream(AuditEventType.values()).filter(type -> type.category() == AuditCategory.ACCESS))
                .containsExactlyInAnyOrderElementsOf(expected);
    }

    private static List<Class<?>> controllers() throws ClassNotFoundException {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(RestController.class));
        List<Class<?>> controllers = new java.util.ArrayList<>();
        for (BeanDefinition definition : scanner.findCandidateComponents("com.certmanagement")) {
            controllers.add(Class.forName(definition.getBeanClassName()));
        }
        assertThat(controllers).hasSizeGreaterThan(20);
        return controllers;
    }
}
