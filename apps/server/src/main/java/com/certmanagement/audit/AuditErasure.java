// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.audit;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;

/**
 * GDPR erasure of members from the audit trail (Art. 17; the rows themselves are kept under
 * Art. 17(3)(e)): every row an erased member acted in reads {@link AuditEventStore#ERASED_ACTOR_LABEL}
 * instead of their name. Rows about the member need nothing: their name is never stored there
 * ({@link AuditEventType#rendersTargetWhenRead()}). The only way code outside this package reaches the
 * erasure, so {@link AuditEventStore} stays private to it.
 */
@Component
public class AuditErasure {

    private final AuditEventStore store;

    public AuditErasure(AuditEventStore store) {
        this.store = store;
    }

    /**
     * Pseudonymises the members in the caller's transaction, so the erasure commits or rolls back with
     * the deletion of the users.
     *
     * @return the audit rows changed
     * @throws org.springframework.transaction.IllegalTransactionStateException when no transaction is active
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public int eraseMembers(Collection<Integer> userIds) {
        return store.pseudonymiseActors(userIds);
    }
}
