// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.classreading.SimpleMetadataReaderFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.annotation.Schedules;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads the production class files (never test classes, no Spring context) to find every background
 * job: methods Spring would schedule, {@link DrainableCron} implementations, and classes that use a
 * scheduler programmatically. Shared by the registration and continuation reachability tests.
 */
final class ProductionJobScan {

    private static final String CLASS_FILES = "classpath*:com/certmanagement/**/*.class";
    private static final MetadataReaderFactory READERS = new SimpleMetadataReaderFactory();

    /**
     * Types a class uses to schedule work itself, as they appear in its constant pool. Executors'
     * scheduled factories return {@code ScheduledExecutorService}, so they are covered too.
     */
    static final List<String> SCHEDULER_TYPES = List.of(
            "org/springframework/scheduling/TaskScheduler",
            "org/springframework/scheduling/concurrent/ThreadPoolTaskScheduler",
            "org/springframework/scheduling/annotation/SchedulingConfigurer",
            "org/springframework/scheduling/config/ScheduledTaskRegistrar",
            "java/util/concurrent/ScheduledExecutorService",
            "java/util/concurrent/ScheduledThreadPoolExecutor",
            "java/util/Timer");

    private static List<Resource> productionClassFiles;

    private ProductionJobScan() {
    }

    /** Production classes declaring at least one method Spring schedules (see {@link #isScheduled}). */
    static List<Class<?>> scheduledOwners() {
        return productionClassFiles().stream()
                .map(ProductionJobScan::read)
                .filter(ProductionJobScan::declaresScheduledMethods)
                .<Class<?>>map(reader -> load(reader.getClassMetadata().getClassName()))
                .toList();
    }

    /** Concrete production {@link DrainableCron} implementations. */
    static List<Class<?>> drainableCrons() {
        return productionClassFiles().stream()
                .map(ProductionJobScan::read)
                .filter(ProductionJobScan::mayImplementDrainableCron)
                .map(reader -> reader.getClassMetadata().getClassName())
                .map(ProductionJobScan::load)
                .filter(DrainableCron.class::isAssignableFrom)
                .filter(type -> !type.isInterface() && !Modifier.isAbstract(type.getModifiers()))
                .toList();
    }

    /** Implements it directly, or extends a class (other than Object) that may; loads only those. */
    private static boolean mayImplementDrainableCron(MetadataReader reader) {
        return Arrays.asList(reader.getClassMetadata().getInterfaceNames()).contains(DrainableCron.class.getName())
                || !Object.class.getName().equals(reader.getClassMetadata().getSuperClassName());
    }

    /** Top-level production classes (nested classes count as their owner) referencing a scheduler type. */
    static Set<String> programmaticSchedulerUsers() {
        Set<String> users = new TreeSet<>();
        for (Resource classFile : productionClassFiles()) {
            String constantPool = new String(bytes(classFile), StandardCharsets.ISO_8859_1);
            if (SCHEDULER_TYPES.stream().anyMatch(constantPool::contains)) {
                String className = read(classFile).getClassMetadata().getClassName();
                int nested = className.indexOf('$');
                users.add(nested < 0 ? className : className.substring(0, nested));
            }
        }
        return users;
    }

    /**
     * Whether the class file declares a method Spring would schedule, read without loading the class:
     * {@code @Scheduled} directly or as a meta-annotation, or repeated (the {@code @Schedules}
     * container).
     */
    static boolean declaresScheduledMethods(MetadataReader reader) {
        return reader.getAnnotationMetadata().hasAnnotatedMethods(Scheduled.class.getName())
                || reader.getAnnotationMetadata().hasAnnotatedMethods(Schedules.class.getName());
    }

    /** Whether Spring schedules {@code method}: the same lookup ScheduledAnnotationBeanPostProcessor makes. */
    static boolean isScheduled(Method method) {
        return !AnnotatedElementUtils.getMergedRepeatableAnnotations(method, Scheduled.class, Schedules.class)
                .isEmpty();
    }

    /** The scheduled methods of {@code owners}. */
    static List<Method> scheduledMethods(List<Class<?>> owners) {
        List<Method> methods = new ArrayList<>();
        owners.forEach(owner -> Arrays.stream(owner.getDeclaredMethods())
                .filter(ProductionJobScan::isScheduled)
                .forEach(methods::add));
        return methods;
    }

    static MetadataReader read(Class<?> type) {
        try {
            return READERS.getMetadataReader(type.getName());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static synchronized List<Resource> productionClassFiles() {
        if (productionClassFiles == null) {
            try {
                productionClassFiles = Arrays.stream(new PathMatchingResourcePatternResolver().getResources(CLASS_FILES))
                        .filter(ProductionJobScan::isProductionClass)
                        .toList();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return productionClassFiles;
    }

    private static boolean isProductionClass(Resource resource) {
        try {
            return !resource.getURL().toString().contains("/test-classes/");
        } catch (IOException e) {
            return true;
        }
    }

    private static MetadataReader read(Resource classFile) {
        try {
            return READERS.getMetadataReader(classFile);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] bytes(Resource classFile) {
        try {
            return classFile.getContentAsByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Class<?> load(String className) {
        try {
            return Class.forName(className, false, ProductionJobScan.class.getClassLoader());
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }
}
