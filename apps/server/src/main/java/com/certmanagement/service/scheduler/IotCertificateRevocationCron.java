// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.scheduler;

import com.certmanagement.iot.revocation.IotRevocationDispatchStore;
import com.certmanagement.iot.config.IotRevocationProperties;
import com.certmanagement.messaging.CertAgentPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

@Slf4j
@Service
@CronJobFor("process-iot-certificate-revocations")
@RequiredArgsConstructor
public class IotCertificateRevocationCron implements DrainableCron {
    private final IotRevocationDispatchStore store;
    private final CertAgentPublisher publisher;
    private final IotRevocationProperties properties;

    @Override
    public boolean tryProcessOneEligible() {
        IotRevocationDispatchStore.ClaimBatch batch = store.claimBatch();
        if (!batch.foundRows()) return false;
        Map<String, String> parentMdc = MDC.getCopyOfContextMap();
        List<Callable<IotRevocationDispatchStore.PublishOutcome>> tasks = batch.claims().stream()
                .<Callable<IotRevocationDispatchStore.PublishOutcome>>map(claim ->
                        () -> publish(claim, parentMdc)).toList();
        List<IotRevocationDispatchStore.PublishOutcome> outcomes = new ArrayList<>(tasks.size());
        try (ExecutorService executor = Executors.newFixedThreadPool(
                properties.getPublishConcurrency(),
                Thread.ofVirtual().name("iot-revocation-publish-", 0).factory())) {
            try {
                List<Future<IotRevocationDispatchStore.PublishOutcome>> futures =
                        executor.invokeAll(tasks);
                for (Future<IotRevocationDispatchStore.PublishOutcome> future : futures) {
                    outcomes.add(future.get());
                }
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                log.warn("IoT revocation publishing interrupted; unresolved claims will retry after lease expiry");
            } catch (ExecutionException exception) {
                throw new IllegalStateException("Unexpected IoT revocation publisher failure",
                        exception.getCause());
            }
        }
        store.completeBatch(outcomes);
        return true;
    }

    private IotRevocationDispatchStore.PublishOutcome publish(
            IotRevocationDispatchStore.Claim claim, Map<String, String> parentMdc) {
        if (parentMdc != null) MDC.setContextMap(parentMdc);
        MDC.put("requestId", claim.command().getRequestId());
        MDC.put("correlationId", claim.command().getCorrelationId());
        MDC.put("organizationId", claim.command().getOrganizationId());
        try {
            publisher.publishIotCertificateRevocation(claim.command());
            return IotRevocationDispatchStore.PublishOutcome.published(claim);
        } catch (RuntimeException exception) {
            log.warn("IoT revocation publish failed operation={} attempt={}: {}",
                    claim.command().getOperationXref(), claim.attempt(), exception.getMessage());
            return IotRevocationDispatchStore.PublishOutcome.failed(
                    claim, "queue publish failed");
        } finally {
            MDC.clear();
        }
    }
}
