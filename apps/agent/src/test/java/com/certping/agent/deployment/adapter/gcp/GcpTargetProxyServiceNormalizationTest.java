// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.deployment.adapter.gcp;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Direct unit tests for the URL normalization helpers in {@link GcpTargetProxyService}.
 *
 * <p>These exist alongside the adapter integration tests because the normalization logic decides
 * what we put on the wire to GCP — getting it wrong manifests only as runtime 400s from Compute or
 * (worse) cert-list drift on a Target Proxy that accumulates duplicate logical entries until the
 * per-proxy cert limit is hit. Drift is subtle because GCP <em>accepts</em> both
 * {@code //certificatemanager.googleapis.com/...} and {@code https://certificatemanager.googleapis.com/v1.../...}
 * as valid CM URLs on the read side, but the merge/compare logic in
 * {@link GcpDeploymentSupport#mergeCertificateLists} only de-dupes on string equality — so any
 * canonicalization gap turns silently into duplicate entries on the next deploy.
 *
 * <p>The cases cover both the "{@code normalizeForCompute → wire}" direction and the
 * "{@code wire → denormalizeFromCompute → bare}" inverse, plus the shared
 * {@code stripCertManagerPrefix} helper used by both.
 */
class GcpTargetProxyServiceNormalizationTest {

    // ------------------------------------------------------------------ //
    //  stripCertManagerPrefix — recognises all accepted Certificate Manager URL shapes
    // ------------------------------------------------------------------ //

    @Test
    void stripCertManagerPrefix_canonicalCrossServiceForm_returnsBareResourceName() {
        // Canonical wire form — what we emit and what compute returns most often.
        String input = "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input))
                .isEqualTo("projects/p1/locations/global/certificates/c1");
    }

    @Test
    void stripCertManagerPrefix_httpsAlternateForm_v1_returnsBareResourceName() {
        // GCP also stores entries in https://certificatemanager.googleapis.com/v1/... form on
        // older proxies. Must collapse to the same bare name so equality checks during merge
        // recognise it as the same logical resource.
        String input = "https://certificatemanager.googleapis.com/v1/projects/p1/locations/us-central1/certificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input))
                .isEqualTo("projects/p1/locations/us-central1/certificates/c1");
    }

    @Test
    void stripCertManagerPrefix_httpsAlternateForm_v1alpha1_returnsBareResourceName() {
        // v1alpha1 was the original public Certificate Manager API version; some early-adopter
        // GCP projects still report entries in this form on read paths.
        String input = "https://certificatemanager.googleapis.com/v1alpha1/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input))
                .isEqualTo("projects/p1/locations/global/certificates/c1");
    }

    @Test
    void stripCertManagerPrefix_httpsAlternateForm_v1beta1_returnsBareResourceName() {
        // Defensive — we don't pin the version segment, so any future v1betaN should also parse.
        String input = "https://certificatemanager.googleapis.com/v1beta1/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input))
                .isEqualTo("projects/p1/locations/global/certificates/c1");
    }

    @Test
    void stripCertManagerPrefix_httpsAlternateAuthority_butNotACertResource_returnsNull() {
        // Authority matches but the body isn't a CM resource path (could be a different resource
        // type under the same domain). Must NOT misclassify — return null so the caller leaves
        // the original value untouched rather than mangling it.
        String input = "https://certificatemanager.googleapis.com/v1/projects/p1/locations/global/dnsAuthorizations/a1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input)).isNull();
    }

    @Test
    void stripCertManagerPrefix_nativeComputeFullSelfLink_returnsNull() {
        String input = "https://www.googleapis.com/compute/v1/projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input)).isNull();
    }

    @Test
    void stripCertManagerPrefix_partialNativeComputeUrl_returnsNull() {
        String input = "projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input)).isNull();
    }

    @Test
    void stripCertManagerPrefix_bareCertManagerResourceName_returnsNull() {
        // Bare resource name is not a URL per se — stripCertManagerPrefix only strips known
        // prefixes. normalizeForCompute handles this case by recognizing the bare-name shape
        // separately and prefixing it. Asserted here so a future refactor doesn't merge the two
        // responsibilities and accidentally break round-tripping.
        String input = "projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input)).isNull();
    }

    @Test
    void stripCertManagerPrefix_nullOrBlank_returnsNull() {
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(null)).isNull();
        assertThat(GcpTargetProxyService.stripCertManagerPrefix("")).isNull();
        assertThat(GcpTargetProxyService.stripCertManagerPrefix("   ")).isNull();
    }

    @Test
    void stripCertManagerPrefix_leadingTrailingWhitespace_isTolerated() {
        // Proxy-reported entries from older deploys occasionally had stray whitespace from manual
        // edits. Tolerating it here avoids re-adding logically duplicate entries on the next deploy.
        String input = "  //certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1  ";
        assertThat(GcpTargetProxyService.stripCertManagerPrefix(input))
                .isEqualTo("projects/p1/locations/global/certificates/c1");
    }

    // ------------------------------------------------------------------ //
    //  normalizeForCompute — collapses every CM input form to the canonical wire form
    // ------------------------------------------------------------------ //

    @Test
    void normalizeForCompute_bareCertManagerResourceName_isPrefixedWithCanonicalCrossService() {
        String input = "projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of(input)))
                .containsExactly("//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1");
    }

    @Test
    void normalizeForCompute_canonicalCrossServiceForm_isPassedThroughUnchanged() {
        // Idempotency: running normalizeForCompute twice produces the same output.
        String input = "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of(input)))
                .containsExactly(input);
    }

    @Test
    void normalizeForCompute_httpsAlternateForm_isCollapsedToCanonical() {
        // This is the critical anti-drift case — the HTTPS alternate form arrives from existing
        // proxy state on read, gets fed back into normalizeForCompute on the next deploy via
        // mergeCertificateLists, and must collapse to the same canonical string as the freshly
        // created cert so the merge de-dupes correctly.
        String input = "https://certificatemanager.googleapis.com/v1/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of(input)))
                .containsExactly("//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1");
    }

    @Test
    void normalizeForCompute_nativeComputeSelfLink_isPassedThroughUnchanged() {
        // Native compute URLs must not be prefixed — Compute would reject them as malformed.
        String input = "https://www.googleapis.com/compute/v1/projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of(input)))
                .containsExactly(input);
    }

    @Test
    void normalizeForCompute_partialNativeComputeUrl_isPassedThroughUnchanged() {
        String input = "projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of(input)))
                .containsExactly(input);
    }

    @Test
    void normalizeForCompute_mixedShapes_areAllCanonicalizedConsistently() {
        // Realistic merged list from a Target HTTPS Proxy that has both native compute and CM
        // entries — and one CM entry in each accepted shape. After normalize, all CM entries
        // collapse to the canonical form; native entry is untouched.
        List<String> mixed = Arrays.asList(
                "projects/p1/locations/global/certificates/c1",                                        // bare CM
                "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c2",    // canonical CM
                "https://certificatemanager.googleapis.com/v1/projects/p1/locations/global/certificates/c3", // https CM
                "projects/p1/global/sslCertificates/native");                                          // native compute
        assertThat(GcpTargetProxyService.normalizeForCompute(mixed))
                .containsExactly(
                        "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1",
                        "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c2",
                        "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c3",
                        "projects/p1/global/sslCertificates/native");
    }

    @Test
    void normalizeForCompute_nullsAndBlanks_areDropped() {
        List<String> mixed = Arrays.asList(
                null,
                "",
                "   ",
                "projects/p1/locations/global/certificates/c1");
        assertThat(GcpTargetProxyService.normalizeForCompute(mixed))
                .containsExactly("//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1");
    }

    @Test
    void normalizeForCompute_emptyInput_returnsEmptyList() {
        assertThat(GcpTargetProxyService.normalizeForCompute(List.of())).isEmpty();
        assertThat(GcpTargetProxyService.normalizeForCompute(null)).isEmpty();
    }

    // ------------------------------------------------------------------ //
    //  denormalizeFromCompute — strips every recognised CM prefix; preserves the rest
    // ------------------------------------------------------------------ //

    @Test
    void denormalizeFromCompute_canonicalCrossServicePrefix_isStripped() {
        String input = "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.denormalizeFromCompute(List.of(input)))
                .containsExactly("projects/p1/locations/global/certificates/c1");
    }

    @Test
    void denormalizeFromCompute_httpsAlternateForm_isStripped() {
        // Symmetry with normalizeForCompute — both must recognise the HTTPS alternate so a CM
        // entry stored by an older deploy in https://... form is reduced to the same bare name as
        // a freshly-emitted canonical entry, letting mergeCertificateLists de-dup correctly.
        String input = "https://certificatemanager.googleapis.com/v1alpha1/projects/p1/locations/global/certificates/c1";
        assertThat(GcpTargetProxyService.denormalizeFromCompute(List.of(input)))
                .containsExactly("projects/p1/locations/global/certificates/c1");
    }

    @Test
    void denormalizeFromCompute_nativeComputeFullSelfLink_isPassedThroughUnchanged() {
        String input = "https://www.googleapis.com/compute/v1/projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.denormalizeFromCompute(List.of(input)))
                .containsExactly(input);
    }

    @Test
    void denormalizeFromCompute_partialNativeComputeUrl_isPassedThroughUnchanged() {
        String input = "projects/p1/global/sslCertificates/c1";
        assertThat(GcpTargetProxyService.denormalizeFromCompute(List.of(input)))
                .containsExactly(input);
    }

    @Test
    void denormalizeFromCompute_mixedShapes_areReducedToOneNamespacePerKind() {
        // Same realistic mix as the normalize test, but coming back the other way — from the
        // proxy's reported sslCertificatesList through to the bare CM names + unchanged compute
        // URLs that mergeCertificateLists operates on.
        List<String> mixed = Arrays.asList(
                "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1",
                "https://certificatemanager.googleapis.com/v1/projects/p1/locations/global/certificates/c2",
                "https://www.googleapis.com/compute/v1/projects/p1/global/sslCertificates/native");
        assertThat(GcpTargetProxyService.denormalizeFromCompute(mixed))
                .containsExactly(
                        "projects/p1/locations/global/certificates/c1",
                        "projects/p1/locations/global/certificates/c2",
                        "https://www.googleapis.com/compute/v1/projects/p1/global/sslCertificates/native");
    }

    @Test
    void denormalizeFromCompute_nullsAreSkipped_emptyAndBlanksPreservedAsBareValues() {
        // Defensive: GCP shouldn't ever report a null in the cert list, but if it ever did we
        // want to skip rather than NPE. Empty strings would only show up from a malformed input
        // path; we pass them through unchanged so a caller that expects a stable list size sees
        // them and can decide what to do.
        List<String> mixed = Arrays.asList(
                null,
                "",
                "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1");
        assertThat(GcpTargetProxyService.denormalizeFromCompute(mixed))
                .containsExactly("", "projects/p1/locations/global/certificates/c1");
    }

    @Test
    void denormalizeFromCompute_emptyInput_returnsEmptyList() {
        assertThat(GcpTargetProxyService.denormalizeFromCompute(List.of())).isEmpty();
        assertThat(GcpTargetProxyService.denormalizeFromCompute(null)).isEmpty();
    }

    // ------------------------------------------------------------------ //
    //  Round-trip symmetry — the property the de-dupe correctness depends on
    // ------------------------------------------------------------------ //

    @Test
    void roundTrip_denormalizeThenNormalize_collapsesAllCmFormsToTheSameCanonical() {
        // The critical correctness property: regardless of which CM URL shape a proxy reports,
        // running denormalizeFromCompute followed by normalizeForCompute on the result produces
        // the canonical wire form. This is what makes mergeCertificateLists able to recognise
        // logically-identical entries on repeated deploys and avoid duplicate accumulation.
        String canonical = "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1";

        for (String inputShape : List.of(
                "//certificatemanager.googleapis.com/projects/p1/locations/global/certificates/c1",
                "https://certificatemanager.googleapis.com/v1/projects/p1/locations/global/certificates/c1",
                "https://certificatemanager.googleapis.com/v1alpha1/projects/p1/locations/global/certificates/c1",
                "https://certificatemanager.googleapis.com/v1beta1/projects/p1/locations/global/certificates/c1")) {
            List<String> denormalized = GcpTargetProxyService.denormalizeFromCompute(List.of(inputShape));
            List<String> renormalized = GcpTargetProxyService.normalizeForCompute(denormalized);
            assertThat(renormalized)
                    .as("round-trip from input shape: %s", inputShape)
                    .containsExactly(canonical);
        }
    }
}
