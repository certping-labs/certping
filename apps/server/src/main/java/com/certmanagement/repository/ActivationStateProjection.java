// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.repository;

/**
 * Activation and soft-delete flags read without materialising the owning entity. Used on request
 * paths that only need to know whether an account is still usable.
 */
public interface ActivationStateProjection {

    /**
     * Nullable in the schema, and deliberately returned as {@code Boolean} rather than
     * {@code boolean}: callers must treat anything that is not {@code TRUE} as unusable. A getter
     * whose alias stops resolving returns {@code null} silently rather than failing, so a null here
     * means either the column is null or the query no longer matches this interface.
     */
    Boolean getActive();

    Boolean getIsDeleted();
}
