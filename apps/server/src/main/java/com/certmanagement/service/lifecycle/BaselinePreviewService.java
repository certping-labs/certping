// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certmanagement.service.lifecycle;

import com.certmanagement.dto.featureflags.BaselinePreviewResponse;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.CausePreview;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.FeaturePreview;
import com.certmanagement.dto.featureflags.BaselinePreviewResponse.ItemCount;
import com.certmanagement.service.FeatureFlagDecision.OffCause;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What the BASELINE would pause if the {@code FEATURE_LIFECYCLE_RECONCILE} switch were turned on now:
 * per feature, the organizations and records, by the layer that has the feature off. Read only.
 *
 * <p>Pages the organizations holding active records exactly as the sweep does and selects them with
 * the same {@link BaselineClassifier}, so it shows what the sweep then pauses (organizations with a
 * forced change still being applied are left out of both). Each page costs a fixed six queries; the
 * walk is bounded by the organizations that hold active records, and the endpoint is super admin only
 * and run once per environment before the switch goes on.
 */
@Service
@RequiredArgsConstructor
public class BaselinePreviewService {

    private final FeatureLifecycleRegistry registry;
    private final BaselineClassifier classifier;

    @Transactional(readOnly = true)
    public BaselinePreviewResponse preview() {
        List<FeaturePreview> features = new ArrayList<>();
        for (PlatformPausableLifecycle lifecycle : registry.pausable()) {
            features.add(previewFeature(lifecycle));
        }
        return new BaselinePreviewResponse(features);
    }

    private FeaturePreview previewFeature(PlatformPausableLifecycle lifecycle) {
        Map<OffCause, CauseTally> byCause = new EnumMap<>(OffCause.class);
        long after = 0;
        List<Long> page = lifecycle.organizationsWithActiveRecords(after, FeatureLifecycleSweeper.PAGE_SIZE);
        while (!page.isEmpty()) {
            Map<Long, OffCause> candidates = classifier.baselineCandidates(lifecycle.featureKey(), page);
            Map<Long, List<AffectedItems>> items = lifecycle.activeItems(candidates.keySet());
            candidates.forEach((organizationId, cause) -> byCause.computeIfAbsent(cause, key -> new CauseTally())
                    .add(items.getOrDefault(organizationId, List.of())));
            after = page.get(page.size() - 1);
            page = lifecycle.organizationsWithActiveRecords(after, FeatureLifecycleSweeper.PAGE_SIZE);
        }
        List<CausePreview> causes = new ArrayList<>();
        long organizations = 0;
        long records = 0;
        for (Map.Entry<OffCause, CauseTally> entry : byCause.entrySet()) {
            CauseTally tally = entry.getValue();
            causes.add(new CausePreview(entry.getKey().name(), tally.organizations, tally.records(), tally.items()));
            organizations += tally.organizations;
            records += tally.records();
        }
        return new FeaturePreview(lifecycle.featureKey(), organizations, records, causes);
    }

    /** Running totals of one cause. */
    private static final class CauseTally {
        private long organizations;
        private final Map<BlockerKind, ItemCount> byKind = new LinkedHashMap<>();

        void add(List<AffectedItems> organizationItems) {
            organizations++;
            for (AffectedItems item : organizationItems) {
                byKind.merge(item.kind(), new ItemCount(item.kind().name(), item.label(), item.count()),
                        (a, b) -> new ItemCount(a.kind(), a.label(), a.count() + b.count()));
            }
        }

        long records() {
            return byKind.values().stream().mapToLong(ItemCount::count).sum();
        }

        List<ItemCount> items() {
            return List.copyOf(byKind.values());
        }
    }
}
