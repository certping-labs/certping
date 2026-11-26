// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.testing;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

/** {@link ObjectProvider}s for unit tests that construct a bean by hand. */
public final class BeanProviders {

    private BeanProviders() {
    }

    /** A provider that hands out {@code bean}, as the container would for its only candidate. */
    public static <T> ObjectProvider<T> of(Class<T> type, T bean) {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        beanFactory.registerSingleton(type.getName(), bean);
        return beanFactory.getBeanProvider(type);
    }
}
