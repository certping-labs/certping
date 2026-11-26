// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.stereotype.Component;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring can only create a component whose constructor it can choose: a single constructor, a
 * no-argument one, or one marked {@code @Autowired}. Unit tests build components by hand, so a
 * second constructor (for example a package-private one taking a test clock) passes every unit
 * test and then stops the agent from starting. This check catches that without starting Spring.
 */
class ComponentConstructorTest {

    @Test
    void everyComponentHasAConstructorSpringCanChoose() throws Exception {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Component.class));

        List<String> ambiguous = new ArrayList<>();
        int checked = 0;
        for (BeanDefinition candidate : scanner.findCandidateComponents("com.certping.agent")) {
            Class<?> type = Class.forName(candidate.getBeanClassName());
            if (type.isInterface() || Modifier.isAbstract(type.getModifiers())) {
                continue;
            }
            checked++;
            Constructor<?>[] constructors = type.getDeclaredConstructors();
            if (constructors.length <= 1) {
                continue;
            }
            boolean hasNoArg = Arrays.stream(constructors).anyMatch(c -> c.getParameterCount() == 0);
            long autowired = Arrays.stream(constructors).filter(c -> c.isAnnotationPresent(Autowired.class)).count();
            if (!hasNoArg && autowired != 1) {
                ambiguous.add(type.getName());
            }
        }

        assertThat(checked).as("components scanned").isGreaterThan(20);
        assertThat(ambiguous)
                .as("components with several constructors and none marked @Autowired")
                .isEmpty();
    }
}
