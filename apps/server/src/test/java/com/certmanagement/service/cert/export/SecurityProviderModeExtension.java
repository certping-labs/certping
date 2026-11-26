// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.cert.export;

import org.junit.jupiter.api.extension.Extension;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContext;
import org.junit.jupiter.api.extension.TestTemplateInvocationContextProvider;

import java.lang.reflect.Method;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

/**
 * Backs {@link AcrossSecurityProviderModes}: one invocation per {@link SecurityProviderMode}, each
 * running the test body with the provider list rearranged for that mode. A snapshot of the list is
 * taken first and restored in a {@code finally}, to the same instances in the same positions, so the
 * mode never leaks into the next test. {@code @BeforeEach} and {@code @AfterEach} run outside it.
 */
final class SecurityProviderModeExtension implements TestTemplateInvocationContextProvider {

    @Override
    public boolean supportsTestTemplate(ExtensionContext context) {
        return true;
    }

    @Override
    public Stream<TestTemplateInvocationContext> provideTestTemplateInvocationContexts(ExtensionContext context) {
        return Arrays.stream(SecurityProviderMode.values()).map(ModeInvocation::new);
    }

    private record ModeInvocation(SecurityProviderMode mode) implements TestTemplateInvocationContext {

        @Override
        public String getDisplayName(int invocationIndex) {
            return "[" + mode.displayName() + "]";
        }

        @Override
        public List<Extension> getAdditionalExtensions() {
            return List.of(new ProviderListSwap(mode));
        }
    }

    private record ProviderListSwap(SecurityProviderMode mode) implements InvocationInterceptor {

        @Override
        public void interceptTestTemplateMethod(Invocation<Void> invocation,
                                                ReflectiveInvocationContext<Method> invocationContext,
                                                ExtensionContext extensionContext) throws Throwable {
            Provider[] snapshot = Security.getProviders();
            try {
                mode.apply();
                invocation.proceed();
            } finally {
                restore(snapshot);
            }
        }
    }

    /**
     * Runs {@code action} under {@code mode} outside any test template, restoring the provider list
     * exactly afterwards, e.g. to build or read material the way a stock JDK would.
     */
    static <T> T callIn(SecurityProviderMode mode, Callable<T> action) throws Exception {
        Provider[] snapshot = Security.getProviders();
        try {
            mode.apply();
            return action.call();
        } finally {
            restore(snapshot);
        }
    }

    /**
     * Removes every provider that is not the snapshot's instance under that name, then re-inserts the
     * snapshot's missing ones at their original positions. Ascending insertion order keeps every
     * earlier position fixed, so the result is the snapshot exactly; anything else fails the test.
     */
    static void restore(Provider[] snapshot) {
        List<Provider> expected = List.of(snapshot);
        for (Provider current : Security.getProviders()) {
            if (expected.stream().noneMatch(original -> original == current)) {
                Security.removeProvider(current.getName());
            }
        }
        for (int i = 0; i < snapshot.length; i++) {
            if (Security.getProvider(snapshot[i].getName()) == null) {
                Security.insertProviderAt(snapshot[i], i + 1);
            }
        }
        if (!isSameProviderList(Security.getProviders(), snapshot)) {
            throw new IllegalStateException("Security provider list was not restored: "
                    + Arrays.toString(Security.getProviders()) + " != " + Arrays.toString(snapshot));
        }
    }

    private static boolean isSameProviderList(Provider[] actual, Provider[] expected) {
        if (actual.length != expected.length) {
            return false;
        }
        for (int i = 0; i < actual.length; i++) {
            if (actual[i] != expected[i]) {
                return false;
            }
        }
        return true;
    }
}
