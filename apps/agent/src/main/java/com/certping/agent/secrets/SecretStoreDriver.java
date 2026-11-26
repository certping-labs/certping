// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.secrets;

public interface SecretStoreDriver extends SecretStore {

    @Override
    SecretStoreProvider provider();

    boolean parsesHandle(String handle);

    void assertValidName(String name);
}
