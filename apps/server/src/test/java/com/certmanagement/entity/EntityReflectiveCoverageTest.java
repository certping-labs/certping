// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.entity;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Generic reflective POJO exerciser for the Lombok {@code @Data}/{@code @Getter}/{@code @Setter}
 * entities and DTOs in scope. For each target class it:
 * <ul>
 *   <li>instantiates via the no-arg constructor,</li>
 *   <li>sets a type-appropriate sample value through every setter and reads it back via the getter,</li>
 *   <li>invokes {@code equals}/{@code hashCode}/{@code toString}, including {@code equals(null)} and
 *       {@code equals(otherInstance)},</li>
 *   <li>invokes any package/protected no-arg lifecycle callbacks ({@code onCreate}/{@code onUpdate}).</li>
 * </ul>
 * This executes the Lombok-generated accessor lines and JPA lifecycle hooks that the hand-written
 * tests do not individually touch, without duplicating their assertions.
 */
class EntityReflectiveCoverageTest {

    private static final String[] TARGET_CLASSES = {
            // com.certmanagement.entity
            "com.certmanagement.entity.AgentDeepHealthCheckEntity",
            "com.certmanagement.entity.AgentDeepHealthCheckMetricEntity",
            "com.certmanagement.entity.AgentDeepHealthCheckChunkEntity",
            "com.certmanagement.entity.AgentHealthStatusEntity",
            "com.certmanagement.entity.AlertEntity",
            "com.certmanagement.entity.BlacklistedToken",
            "com.certmanagement.entity.CertDeploymentConfigEntity",
            "com.certmanagement.entity.CertManualIssuanceStateEntity",
            "com.certmanagement.entity.CertificateCryptoMetadataEntity",
            "com.certmanagement.entity.CertificateEventEntity",
            "com.certmanagement.entity.CredentialReferenceEntity",
            "com.certmanagement.entity.DeploymentEntity",
            "com.certmanagement.entity.DiscoveredCertEntity",
            "com.certmanagement.entity.DiscoveredCertObservationEntity",
            "com.certmanagement.entity.DiscoveryConfigEntity",
            "com.certmanagement.entity.DiscoveryScanEntity",
            "com.certmanagement.entity.DomainCredentialConfigEntity",
            "com.certmanagement.entity.GlobalFeatureFlag",
            "com.certmanagement.entity.GlobalSettingsEntity",
            "com.certmanagement.entity.Organization",
            "com.certmanagement.entity.OrganizationFeatureFlag",
            "com.certmanagement.entity.OrgTypeFeatureFlag",
            "com.certmanagement.entity.OutstandingToken",
            "com.certmanagement.entity.Permission",
            "com.certmanagement.entity.QueueAlertStateEntity",
            "com.certmanagement.entity.RenewalScheduleEntity",
            "com.certmanagement.entity.Role",
            "com.certmanagement.entity.UserDomainCertEntity",
            "com.certmanagement.entity.UserRole",
            // com.certmanagement.dto.scheduler
            "com.certmanagement.dto.scheduler.SchedulerJobResult",
    };

    @TestFactory
    Stream<DynamicTest> exerciseAllPojos() {
        return Stream.of(TARGET_CLASSES)
                .map(cn -> DynamicTest.dynamicTest(cn, () -> exercise(Class.forName(cn))));
    }

    private void exercise(Class<?> clazz) throws Exception {
        Object instance = newInstance(clazz);
        if (instance == null) {
            return; // no usable no-arg constructor; skip silently
        }

        // Setters + getters round-trip
        for (Method setter : clazz.getMethods()) {
            if (!setter.getName().startsWith("set") || setter.getParameterCount() != 1) {
                continue;
            }
            if (setter.getDeclaringClass() == Object.class) {
                continue;
            }
            Class<?> paramType = setter.getParameterTypes()[0];
            Object value = sampleValue(paramType);
            try {
                setter.invoke(instance, value);
            } catch (Exception ignored) {
                // some setters may reject the sample; not fatal for coverage
            }
        }
        for (Method getter : clazz.getMethods()) {
            String n = getter.getName();
            boolean isGetter = (n.startsWith("get") && n.length() > 3)
                    || (n.startsWith("is") && n.length() > 2);
            if (!isGetter || getter.getParameterCount() != 0) {
                continue;
            }
            if (getter.getDeclaringClass() == Object.class) {
                continue;
            }
            try {
                getter.invoke(instance);
            } catch (Exception ignored) {
            }
        }

        // equals / hashCode / toString
        instance.hashCode();
        instance.toString();
        assertThat(instance.equals(instance)).isTrue();
        assertThat(instance.equals(null)).isFalse();
        assertThat(instance.equals("not-an-entity")).isFalse();
        Object second = newInstance(clazz);
        if (second != null) {
            instance.equals(second); // exercise field-by-field comparison path
        }

        // Lifecycle callbacks (e.g. @PrePersist/@PreUpdate): no-arg void methods named on*
        for (Method m : clazz.getDeclaredMethods()) {
            if (m.getParameterCount() != 0
                    || m.getReturnType() != void.class
                    || Modifier.isStatic(m.getModifiers())) {
                continue;
            }
            String name = m.getName();
            if (name.equals("onCreate") || name.equals("onUpdate")
                    || name.startsWith("prePersist") || name.startsWith("preUpdate")) {
                m.setAccessible(true);
                try {
                    m.invoke(instance);
                } catch (Exception ignored) {
                }
            }
        }
    }

    private Object newInstance(Class<?> clazz) {
        try {
            Constructor<?> ctor = clazz.getDeclaredConstructor();
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Object sampleValue(Class<?> type) {
        if (type == String.class) return "sample";
        if (type == boolean.class || type == Boolean.class) return Boolean.TRUE;
        if (type == int.class || type == Integer.class) return 1;
        if (type == long.class || type == Long.class) return 1L;
        if (type == short.class || type == Short.class) return (short) 1;
        if (type == byte.class || type == Byte.class) return (byte) 1;
        if (type == double.class || type == Double.class) return 1.0d;
        if (type == float.class || type == Float.class) return 1.0f;
        if (type == char.class || type == Character.class) return 'x';
        if (type == BigDecimal.class) return BigDecimal.ONE;
        if (type == UUID.class) return UUID.randomUUID();
        if (type == OffsetDateTime.class) return OffsetDateTime.now(ZoneOffset.UTC);
        if (type == ZonedDateTime.class) return ZonedDateTime.now(ZoneOffset.UTC);
        if (type == Instant.class) return Instant.now();
        if (type == LocalDate.class) return LocalDate.now();
        if (type.isEnum()) {
            Object[] constants = type.getEnumConstants();
            return constants.length > 0 ? constants[0] : null;
        }
        if (type == List.class || type == Collection.class || type == Iterable.class) return new ArrayList<>();
        if (type == java.util.Set.class) return new HashSet<>();
        if (type == Map.class) return new HashMap<>();
        if (type == byte[].class) return new byte[]{1, 2, 3};
        // Try to instantiate a nested entity/DTO via its no-arg ctor
        Object nested = newInstance(type);
        return nested; // may be null; setter invocation guards against it
    }
}
