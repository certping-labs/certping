// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.DevicePlatformType;
import com.certping.agent.model.message.CertificateCorrelationCandidate;
import com.certping.agent.model.message.CertificateCorrelationResult;
import com.certping.agent.model.message.CertificateProfileMessage;
import com.certping.agent.model.message.ProfileObservedState;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateProfileConnectorFactoryTest {

    @Test
    void createsTheConnectorAnnotatedForThePlatformAndSkipsUnannotatedOnes() {
        IntuneConnector intune = new IntuneConnector();
        CertificateProfileConnectorFactory factory =
                new CertificateProfileConnectorFactory(List.of(new UnannotatedConnector(), intune));

        assertThat(factory.create(DevicePlatformType.INTUNE)).isSameAs(intune);
        assertThatThrownBy(() -> factory.create(DevicePlatformType.JAMF))
                .isInstanceOf(PermanentAgentException.class)
                .hasMessageContaining("JAMF");
    }

    @Test
    void duplicatePlatformRegistrationFailsStartup() {
        assertThatThrownBy(() -> new CertificateProfileConnectorFactory(
                List.of(new IntuneConnector(), new IntuneConnector())))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate certificate-profile connector for INTUNE");
    }

    private static class StubConnector implements CertificateProfileConnector {
        @Override public ProfileObservedState create(DeviceSourceProfile source, CertificateProfileMessage command) {
            return null;
        }
        @Override public ProfileObservedState update(DeviceSourceProfile source, CertificateProfileMessage command) {
            return null;
        }
        @Override public void streamProfiles(
                DeviceSourceProfile source, Consumer<List<ProfileObservedState>> pageConsumer) {
        }
        @Override public List<CertificateCorrelationResult> correlateCertificates(
                DeviceSourceProfile source, List<CertificateCorrelationCandidate> candidates) {
            return List.of();
        }
    }

    @CertificateProfileConnectorFor(DevicePlatformType.INTUNE)
    private static final class IntuneConnector extends StubConnector {
    }

    private static final class UnannotatedConnector extends StubConnector {
    }
}
