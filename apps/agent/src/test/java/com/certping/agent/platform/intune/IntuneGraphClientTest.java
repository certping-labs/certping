// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.certping.agent.exception.PermanentAgentException;
import com.certping.agent.exception.RetryableAgentException;
import com.certping.agent.exception.TransientAgentException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IntuneGraphClientTest {

    private static final String MANAGED_DEVICE_ID = "11111111-1111-1111-1111-111111111111";

    @Test
    void syncDeviceTreats204AsSuccess() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class)))
                .thenReturn(ResponseEntity.noContent().build());

        new IntuneGraphClient(rest).syncDevice("token", MANAGED_DEVICE_ID);

        verify(rest).exchange(
                eq("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/"
                        + MANAGED_DEVICE_ID + "/syncDevice"),
                eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class));
    }

    @Test
    void syncDeviceNotFoundIsPermanentDeviceNotFound() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.NOT_FOUND, "n", HttpHeaders.EMPTY, null, null));

        assertThatThrownBy(() -> new IntuneGraphClient(rest).syncDevice("token", MANAGED_DEVICE_ID))
                .isInstanceOf(PermanentAgentException.class)
                .extracting("errorCode").isEqualTo("DEVICE_NOT_FOUND");
    }

    @Test
    void syncDeviceForbiddenSurfacesThePermissionGap() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class)))
                .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN, "f", HttpHeaders.EMPTY, null, null));

        assertThatThrownBy(() -> new IntuneGraphClient(rest).syncDevice("token", MANAGED_DEVICE_ID))
                .isInstanceOf(PermanentAgentException.class)
                .extracting("errorCode").isEqualTo("PERMISSION_DENIED");
    }

    @Test
    void syncDeviceThrottleIsTransient() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(any(String.class), eq(HttpMethod.POST), any(HttpEntity.class), eq(Void.class)))
                .thenThrow(HttpClientErrorException.create(
                        HttpStatus.TOO_MANY_REQUESTS, "t", HttpHeaders.EMPTY, null, null));

        assertThatThrownBy(() -> new IntuneGraphClient(rest).syncDevice("token", MANAGED_DEVICE_ID))
                .isInstanceOf(TransientAgentException.class);
    }

    @Test
    void syncDeviceRejectsNonUuidBeforeCallingGraph() {
        RestTemplate rest = mock(RestTemplate.class);

        assertThatThrownBy(() -> new IntuneGraphClient(rest).syncDevice("token", "../devices"))
                .isInstanceOf(PermanentAgentException.class)
                .extracting("errorCode").isEqualTo("INVALID_MANAGED_DEVICE_ID");

        verify(rest, org.mockito.Mockito.never()).exchange(
                any(String.class), any(HttpMethod.class), any(HttpEntity.class), any(Class.class));
    }

    @Test
    void springSelectsTheProductionRestTemplateBuilderConstructor() {
        try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
            context.getBeanFactory().registerSingleton(
                    "restTemplateBuilder", new RestTemplateBuilder());
            context.register(IntuneGraphClient.class);
            context.refresh();

            assertThat(context.getBean(IntuneGraphClient.class)).isNotNull();
        }
    }

    @Test
    void entraEnrichmentKeepsEveryGraphBatchAtTwentyRequestsOrLess() {
        RestTemplate rest = mock(RestTemplate.class);
        List<Integer> requestSizes = new ArrayList<>();
        when(rest.exchange(eq("https://graph.microsoft.com/v1.0/$batch"), eq(HttpMethod.POST),
                any(HttpEntity.class), eq(Map.class))).thenAnswer(invocation -> {
                    HttpEntity<?> entity = invocation.getArgument(2);
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> requests =
                            (List<Map<String, Object>>) ((Map<?, ?>) entity.getBody()).get("requests");
                    requestSizes.add(requests.size());
                    List<Map<String, Object>> responses = new ArrayList<>();
                    for (Map<String, Object> request : requests) {
                        responses.add(Map.of(
                                "id", request.get("id"),
                                "status", 200,
                                "body", Map.of("id", "object-" + request.get("id"))));
                    }
                    return ResponseEntity.ok(Map.of("responses", responses));
                });
        List<Map<String, Object>> managed = new ArrayList<>();
        for (int index = 0; index < 21; index++) {
            managed.add(Map.of("azureADDeviceId", UUID.randomUUID().toString()));
        }

        Map<String, Map<String, Object>> result =
                new IntuneGraphClient(rest).fetchEntraDevicesForManagedPage("token", managed);

        assertThat(requestSizes).containsExactly(20, 1);
        assertThat(result).hasSize(21);
        verify(rest, times(2)).exchange(eq("https://graph.microsoft.com/v1.0/$batch"),
                eq(HttpMethod.POST), any(HttpEntity.class), eq(Map.class));
    }

    @Test
    void graphTransportFailureRemainsTransient() {
        RestTemplate rest = mock(RestTemplate.class);
        when(rest.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(new ResourceAccessException("timed out"));

        assertThatThrownBy(() -> new IntuneGraphClient(rest).probeManagedDevices("token"))
                .isInstanceOf(TransientAgentException.class)
                .hasMessageContaining("Could not reach Microsoft Graph");
    }

    @Test
    void graphHonorsRetryAfterOnThrottle() {
        RestTemplate rest = mock(RestTemplate.class);
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, "17");
        HttpClientErrorException throttled = HttpClientErrorException.create(
                HttpStatus.TOO_MANY_REQUESTS, "throttled", headers, new byte[0], null);
        when(rest.exchange(any(String.class), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenThrow(throttled);

        assertThatThrownBy(() -> new IntuneGraphClient(rest).probeManagedDevices("token"))
                .isInstanceOfSatisfying(RetryableAgentException.class,
                        exception -> assertThat(exception.getRetryAfter()).isEqualTo(Duration.ofSeconds(17)));
    }
}
