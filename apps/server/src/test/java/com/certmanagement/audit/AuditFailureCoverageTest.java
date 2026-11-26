// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import com.certmanagement.controller.AdminController;
import com.certmanagement.controller.AdminFeatureFlagController;
import com.certmanagement.controller.CertCredentialController;
import com.certmanagement.controller.DataRetentionController;
import com.certmanagement.controller.DomainCredentialConfigController;
import com.certmanagement.controller.FeatureFlagController;
import com.certmanagement.controller.IncidentController;
import com.certmanagement.controller.IntegrationController;
import com.certmanagement.controller.OrganizationController;
import com.certmanagement.controller.RoleController;
import com.certmanagement.controller.UserController;
import org.junit.jupiter.api.Test;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every change endpoint of members, roles, single sign-on, the organization, its features, data retention,
 * credentials and deployment targets records its failures ({@link AuditFailure}), and each annotation's
 * expressions parse and read only the method's own parameters. A new endpoint without the annotation fails here.
 */
class AuditFailureCoverageTest {

    private static final Pattern VARIABLE = Pattern.compile("#([A-Za-z_][A-Za-z0-9_]*)");


    private static boolean isChange(Method method) {
        return AnnotatedElementUtils.hasAnnotation(method, PostMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, PutMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, PatchMapping.class)
                || AnnotatedElementUtils.hasAnnotation(method, DeleteMapping.class);
    }
}
