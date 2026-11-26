// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.testing;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionTemplate;

/** Transaction plumbing for unit tests that need a boundary to exist without a database behind it. */
public final class Transactions {

    private Transactions() {
    }

    /** A template that runs its callback immediately. Use as a {@code @Spy} field under {@code @InjectMocks}. */
    public static TransactionTemplate inline() {
        return new TransactionTemplate(manager());
    }

    /** Spring's real synchronization machinery over no resources, so afterCommit/afterCompletion fire. */
    public static PlatformTransactionManager manager() {
        return new AbstractPlatformTransactionManager() {
            @Override
            protected Object doGetTransaction() {
                return new Object();
            }

            @Override
            protected void doBegin(Object transaction, TransactionDefinition definition) {
            }

            @Override
            protected void doCommit(DefaultTransactionStatus status) {
            }

            @Override
            protected void doRollback(DefaultTransactionStatus status) {
            }
        };
    }
}
