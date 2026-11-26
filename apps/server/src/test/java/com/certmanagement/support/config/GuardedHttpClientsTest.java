// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.support.config;

import com.certmanagement.support.common.ApiException;
import com.certmanagement.support.integrations.domain.IntegrationProvider;
import com.certmanagement.support.integrations.notification.WebhookDeliveryClient;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/** The integration HTTP clients refuse internal destinations when they connect, not only when a URL is saved. */
class GuardedHttpClientsTest {

    private static RestClient client(boolean allowPrivate) {
        return RestClient.builder()
                .requestFactory(GuardedHttpClients.requestFactory(Duration.ofSeconds(2), Duration.ofSeconds(2), allowPrivate))
                .build();
    }

    @Test
    void loopbackMetadataAndPrivateAddressesAreRefusedAtConnect() {
        for (String url : new String[] {
                "https://127.0.0.1/hook", "https://169.254.169.254/latest/meta-data/", "https://10.0.0.5/x",
                "https://[::1]/x", "https://[fd00::1]/x", "https://localhost/x"}) {
            Throwable thrown = catchThrowableOfType(
                    () -> client(false).post().uri(URI.create(url)).retrieve().toBodilessEntity(),
                    ResourceAccessException.class);
            assertThat(thrown).as(url).isNotNull();
            assertThat(rootBlocked(thrown)).as(url).isTrue();
        }
    }

    @Test
    void theOptInLetsAnInstallationPostToItsOwnNetwork() {
        // Nothing listens there: the call fails to connect, but not because the address was refused.
        Throwable thrown = catchThrowableOfType(
                () -> client(true).post().uri(URI.create("https://127.0.0.1:9/hook")).retrieve().toBodilessEntity(),
                ResourceAccessException.class);
        assertThat(thrown).isNotNull();
        assertThat(rootBlocked(thrown)).isFalse();
    }

    @Test
    void aRefusedWebhookDeliveryIsReportedWithoutTheTarget() {
        WebhookDeliveryClient delivery = new WebhookDeliveryClient(client(false));
        assertThatThrownBy(() -> delivery.deliver(IntegrationProvider.TEAMS,
                URI.create("https://169.254.169.254/latest/meta-data/iam"), Map.of("text", "hi")))
                .isInstanceOfSatisfying(ApiException.class, e -> {
                    assertThat(e.code()).isEqualTo("INTEGRATION_DESTINATION_REFUSED");
                    assertThat(e.getMessage()).doesNotContain("169.254");
                });
    }

    private static boolean rootBlocked(Throwable thrown) {
        for (Throwable cause = thrown; cause != null; cause = cause.getCause()) {
            if (cause instanceof GuardedHttpClients.BlockedAddressException) {
                return true;
            }
        }
        return false;
    }
}
