// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.model.enums.TargetType;
import com.certping.agent.model.message.CertDiscoveryMessage;
import com.certping.agent.model.message.DiscoveredCertEntry;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DiscoveryAdapterFactoryTest {

    private DiscoveryAdapter awsAdapter;
    private DiscoveryAdapter kubernetesAdapter;

    private DiscoveryAdapterFactory factory;

    @BeforeEach
    void setUp() {
        awsAdapter = new TestAwsDiscoveryAdapter();
        kubernetesAdapter = new TestKubernetesDiscoveryAdapter();
        factory = new DiscoveryAdapterFactory(List.of(awsAdapter, kubernetesAdapter));
    }

    @Test
    void create_awsAcm_returnsAwsAcmDiscoveryAdapter() {
        DiscoveryAdapter adapter = factory.create(TargetType.AWS_ACM);
        assertThat(adapter).isSameAs(awsAdapter);
    }

    @Test
    void create_awsAlb_returnsAwsAcmDiscoveryAdapter() {
        DiscoveryAdapter adapter = factory.create(TargetType.AWS_ALB);
        assertThat(adapter).isSameAs(awsAdapter);
    }

    @Test
    void create_awsNlb_returnsAwsAcmDiscoveryAdapter() {
        DiscoveryAdapter adapter = factory.create(TargetType.AWS_NLB);
        assertThat(adapter).isSameAs(awsAdapter);
    }

    @Test
    void create_awsCloudFront_returnsAwsAcmDiscoveryAdapter() {
        DiscoveryAdapter adapter = factory.create(TargetType.AWS_CLOUDFRONT);
        assertThat(adapter).isSameAs(awsAdapter);
    }

    @Test
    void create_kubernetesSecrets_returnsKubernetesDiscoveryAdapter() {
        DiscoveryAdapter adapter = factory.create(TargetType.KUBERNETES_SECRETS);
        assertThat(adapter).isSameAs(kubernetesAdapter);
    }

    @Test
    void create_null_throwsPermanentExceptionWithUnknownTargetCode() {
        assertThatThrownBy(() -> factory.create(null))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_UNKNOWN_TARGET"));
    }

    @Test
    void create_unsupportedTargetType_throwsPermanentExceptionWithUnsupportedCode() {
        assertThatThrownBy(() -> factory.create(TargetType.F5_BIGIP))
                .isInstanceOf(PermanentAgentException.class)
                .satisfies(e -> assertThat(((PermanentAgentException) e).getErrorCode())
                        .isEqualTo("DISCOVERY_UNSUPPORTED_TARGET"));
    }

    @DiscoveryAdapterFor({TargetType.AWS_ACM, TargetType.AWS_ALB, TargetType.AWS_NLB, TargetType.AWS_CLOUDFRONT})
    private static final class TestAwsDiscoveryAdapter implements DiscoveryAdapter {
        @Override
        public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
            return List.of();
        }
    }

    @DiscoveryAdapterFor(TargetType.KUBERNETES_SECRETS)
    private static final class TestKubernetesDiscoveryAdapter implements DiscoveryAdapter {
        @Override
        public List<DiscoveredCertEntry> discover(CertDiscoveryMessage message) {
            return List.of();
        }
    }
}
