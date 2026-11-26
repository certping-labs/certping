// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.platform.intune;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

/** Bounded replay protection for Intune's one-download-per-hour connector contract. */
@Component
public class IntuneRevocationReplayCache {
    private static final int MAX_TRANSACTIONS = 512;
    private static final Duration RETENTION = Duration.ofMinutes(75);

    private final Cache<String, List<IntuneRevocationClient.RevocationRequest>> downloads =
            Caffeine.newBuilder().maximumSize(MAX_TRANSACTIONS)
                    .expireAfterWrite(RETENTION).build();
    private final Cache<String, Boolean> uploads = Caffeine.newBuilder()
            .maximumSize(MAX_TRANSACTIONS).expireAfterWrite(RETENTION).build();

    public List<IntuneRevocationClient.RevocationRequest> download(
            String profileRef, String transactionId,
            Supplier<List<IntuneRevocationClient.RevocationRequest>> loader) {
        return downloads.get(key(profileRef, transactionId), ignored -> List.copyOf(loader.get()));
    }

    public boolean wasUploaded(String profileRef, String transactionId) {
        return uploads.getIfPresent(key(profileRef, transactionId)) != null;
    }

    public void markUploaded(String profileRef, String transactionId) {
        uploads.put(key(profileRef, transactionId), Boolean.TRUE);
        downloads.invalidate(key(profileRef, transactionId));
    }

    private static String key(String profileRef, String transactionId) {
        return profileRef + '\0' + transactionId;
    }
}
