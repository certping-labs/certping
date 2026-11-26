// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.CertificateCorrelationCandidate;
import com.certping.agent.model.message.CertificateCorrelationResult;
import com.certping.agent.model.message.ProfileObservedState;

import java.util.List;
import java.util.function.Consumer;

/** Platform boundary for native certificate-profile CRUD and read-only discovery. */
public interface CertificateProfileConnector {
    ProfileObservedState create(DeviceSourceProfile source, CertificateProfileMessage command);

    ProfileObservedState update(DeviceSourceProfile source, CertificateProfileMessage command);

    void streamProfiles(
            DeviceSourceProfile source, Consumer<List<ProfileObservedState>> pageConsumer);

    List<CertificateCorrelationResult> correlateCertificates(
            DeviceSourceProfile source, List<CertificateCorrelationCandidate> candidates);
}
