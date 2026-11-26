// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.discovery.adapter.kubernetes;

import com.certping.agent.kubernetes.KubeApis;

import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.models.V1APIResource;
import io.kubernetes.client.openapi.models.V1APIResourceList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinition;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionSpec;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionVersion;
import io.kubernetes.client.openapi.models.V1ListMeta;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests {@link KubernetesDynamicResourceClient}'s CRD-catalog and namespaced-scan flows.
 * The class is package-private, so this test lives in the same package.
 */
class KubernetesDynamicResourceClientTest {

    private KubernetesDynamicResourceClient client;
    private KubernetesClusterInventory inventory;

    @BeforeEach
    void setUp() {
        client = new KubernetesDynamicResourceClient();
        inventory = new KubernetesClusterInventory();
    }

    // ── loadCatalog ────────────────────────────────────────────────────────

    @Test
    void loadCatalog_alreadyComplete_returnsWithoutApiCall() throws Exception {
        inventory.customResourceCatalogComplete = true;
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);

        client.loadCatalog(api, inventory);

        verify(api, never()).listCustomResourceDefinitions(any(), any());
    }

    @Test
    void loadCatalog_apiReturnsNull_leavesInventoryIncomplete() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(null);

        client.loadCatalog(api, inventory);

        assertThat(inventory.customResourceCatalogComplete).isFalse();
        assertThat(inventory.installedCustomResources).isEmpty();
    }

    @Test
    void loadCatalog_apiReturnsEmptyItems_leavesInventoryIncomplete() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        V1CustomResourceDefinitionList empty = new V1CustomResourceDefinitionList();
        empty.setItems(null);
        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(empty);

        client.loadCatalog(api, inventory);

        assertThat(inventory.customResourceCatalogComplete).isFalse();
    }

    @Test
    void loadCatalog_singlePage_populatesCatalog() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        V1CustomResourceDefinitionList list = new V1CustomResourceDefinitionList();
        list.setItems(List.of(crd("gateways.gateway.networking.k8s.io", true, "v1")));
        list.setMetadata(new V1ListMeta()); // continue == null
        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(list);

        client.loadCatalog(api, inventory);

        assertThat(inventory.customResourceCatalogComplete).isTrue();
        assertThat(inventory.installedCustomResources).contains("gateways.gateway.networking.k8s.io");
        assertThat(inventory.servedCustomResourceVersions.get("gateways.gateway.networking.k8s.io"))
                .containsExactly("v1");
    }

    @Test
    void loadCatalog_multiplePages_continuesUntilTokenBlank() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        V1CustomResourceDefinitionList page1 = new V1CustomResourceDefinitionList();
        page1.setItems(List.of(crd("first.example.com", true, "v1")));
        V1ListMeta meta1 = new V1ListMeta();
        meta1.setContinue("token-next");
        page1.setMetadata(meta1);

        V1CustomResourceDefinitionList page2 = new V1CustomResourceDefinitionList();
        page2.setItems(List.of(crd("second.example.com", true, "v1beta1")));
        page2.setMetadata(new V1ListMeta());

        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(page1, page2);

        client.loadCatalog(api, inventory);

        assertThat(inventory.customResourceCatalogComplete).isTrue();
        assertThat(inventory.installedCustomResources).containsExactlyInAnyOrder(
                "first.example.com", "second.example.com");
        verify(api, times(2)).listCustomResourceDefinitions(any(), any());
    }

    @Test
    void loadCatalog_apiExceptionSwallowed_leavesInventoryIncomplete() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        doThrow(new ApiException(403, "forbidden"))
                .when(api).listCustomResourceDefinitions(any(), any());

        client.loadCatalog(api, inventory);

        assertThat(inventory.customResourceCatalogComplete).isFalse();
    }

    @Test
    void loadCatalog_crdWithoutServedVersions_recordsEmptyVersionSet() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        V1CustomResourceDefinitionList list = new V1CustomResourceDefinitionList();
        list.setItems(List.of(crd("noserved.example.com", false, "v1"))); // served=false
        list.setMetadata(new V1ListMeta());
        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(list);

        client.loadCatalog(api, inventory);

        assertThat(inventory.installedCustomResources).contains("noserved.example.com");
        assertThat(inventory.servedCustomResourceVersions.get("noserved.example.com")).isEmpty();
    }

    @Test
    void loadCatalog_crdMissingName_skipsEntry() throws Exception {
        KubeApis.ApiExtensions api = mock(KubeApis.ApiExtensions.class);
        V1CustomResourceDefinition anon = new V1CustomResourceDefinition();
        anon.setMetadata(new V1ObjectMeta()); // no name set
        V1CustomResourceDefinitionList list = new V1CustomResourceDefinitionList();
        list.setItems(List.of(anon));
        list.setMetadata(new V1ListMeta());
        when(api.listCustomResourceDefinitions(any(), any())).thenReturn(list);

        client.loadCatalog(api, inventory);

        assertThat(inventory.installedCustomResources).isEmpty();
    }

    // ── scanNamespaced ─────────────────────────────────────────────────────

    @Test
    void scanNamespaced_catalogCompleteAndResourceNotInstalled_returnsWithoutApiCall() throws Exception {
        inventory.customResourceCatalogComplete = true;
        // "traefikservices.traefik.io" NOT added → skip
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);

        client.scanNamespaced(api, inventory, "ns", "traefik.io", "v1alpha1",
                "traefikservices", "TraefikService", item -> {});

        verify(api, never()).listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void scanNamespaced_catalogCompleteAndVersionUnsupported_marksUnreadable() throws Exception {
        inventory.customResourceCatalogComplete = true;
        inventory.installedCustomResources.add("traefikservices.traefik.io");
        inventory.servedCustomResourceVersions.put("traefikservices.traefik.io", Set.of("v1"));
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);

        client.scanNamespaced(api, inventory, "ns", "traefik.io", "v1alpha1",
                "traefikservices", "TraefikService", item -> {});

        assertThat(inventory.unreadableResourceTypes).contains("TraefikService");
        assertThat(inventory.warnings).anyMatch(w -> w.contains("TraefikService"));
        verify(api, never()).listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any());
    }

    @Test
    void scanNamespaced_notFoundApiException_returnsSilently() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(eq("g"), eq("v"), eq("ns"), eq("plural"), any(), any()))
                .thenThrow(new ApiException(404, "not found"));

        client.scanNamespaced(api, inventory, "ns", "g", "v", "plural", "Kind", item -> {});

        // 404 is silently absorbed — no warnings, no unreadable marker
        assertThat(inventory.unreadableResourceTypes).doesNotContain("Kind");
        assertThat(inventory.warnings).isEmpty();
    }

    @Test
    void scanNamespaced_forbiddenApiException_marksUnreadable() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(eq("g"), eq("v"), eq("ns"), eq("plural"), any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));

        client.scanNamespaced(api, inventory, "ns", "g", "v", "plural", "Kind", item -> {});

        assertThat(inventory.unreadableResourceTypes).contains("Kind");
        assertThat(inventory.warnings).anyMatch(w -> w.contains("Kind"));
    }

    @Test
    void scanNamespaced_forbiddenAndGroupVersionNotServed_skipsQuietly() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));
        when(api.listApiResources("gateway.networking.k8s.io", "v1")).thenThrow(new ApiException(404, "not found"));

        client.scanNamespaced(api, inventory, "a", "gateway.networking.k8s.io", "v1", "gateways", "Gateway", item -> {});
        client.scanNamespaced(api, inventory, "b", "gateway.networking.k8s.io", "v1", "gateways", "Gateway", item -> {});

        assertThat(inventory.unreadableResourceTypes).isEmpty();
        assertThat(inventory.warnings).isEmpty();
        verify(api, times(1)).listApiResources("gateway.networking.k8s.io", "v1");
    }

    @Test
    void scanNamespaced_forbiddenAndResourceMissingFromServedGroup_skipsQuietly() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));
        when(api.listApiResources("traefik.io", "v1alpha1")).thenReturn(apiResources("ingressroutes"));

        client.scanNamespaced(api, inventory, "ns", "traefik.io", "v1alpha1", "ingressroutetcps",
                "IngressRouteTCP", item -> {});

        assertThat(inventory.unreadableResourceTypes).isEmpty();
        assertThat(inventory.warnings).isEmpty();
    }

    @Test
    void scanNamespaced_forbiddenAndResourceServed_warnsAboutPermission() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new ApiException(403, "forbidden"));
        when(api.listApiResources("traefik.io", "v1alpha1")).thenReturn(apiResources("ingressroutes"));

        client.scanNamespaced(api, inventory, "ns", "traefik.io", "v1alpha1", "ingressroutes",
                "IngressRoute", item -> {});

        assertThat(inventory.unreadableResourceTypes).containsExactly("IngressRoute");
        assertThat(inventory.warnings).containsExactly("Permission denied listing IngressRoute custom resources "
                + "(grant list on ingressroutes.traefik.io); usage and impact are incomplete");
    }

    @Test
    void scanNamespaced_serverError_warnsUnableToList() throws Exception {
        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        when(api.listNamespaced(anyString(), anyString(), anyString(), anyString(), any(), any()))
                .thenThrow(new ApiException(500, "boom"));

        client.scanNamespaced(api, inventory, "ns", "g", "v", "plural", "Kind", item -> {});

        assertThat(inventory.warnings).containsExactly(
                "Unable to list Kind custom resources for Kubernetes discovery; usage and impact are incomplete");
        verify(api, never()).listApiResources(anyString(), anyString());
    }

    @Test
    void scanNamespaced_useCatalogFalse_bypassesCatalogGuards() throws Exception {
        // Force useCatalog=false via the 8-arg overload.
        inventory.customResourceCatalogComplete = true;
        // 'servedVersions' would filter this out, but useCatalog=false bypasses that entirely.
        inventory.installedCustomResources.add("plural.g");
        inventory.servedCustomResourceVersions.put("plural.g", Set.of("some-other-version"));

        KubeApis.CustomObjects api = mock(KubeApis.CustomObjects.class);
        // return null so items() returns empty list — enough to exercise the try path
        when(api.listNamespaced(eq("g"), eq("v"), eq("ns"), eq("plural"), any(), any()))
                .thenReturn(null);

        client.scanNamespaced(api, inventory, "ns", "g", "v", "plural", "Kind", false, item -> {});

        // No unreadable marking; the API WAS called (useCatalog=false skipped the filter).
        assertThat(inventory.unreadableResourceTypes).doesNotContain("Kind");
        verify(api).listNamespaced(eq("g"), eq("v"), eq("ns"), eq("plural"), any(), any());
    }

    // ── helpers ────────────────────────────────────────────────────────────

    private static V1APIResourceList apiResources(String... plurals) {
        V1APIResourceList list = new V1APIResourceList();
        for (String plural : plurals) {
            list.addResourcesItem(new V1APIResource().name(plural));
        }
        return list;
    }

    private static V1CustomResourceDefinition crd(String name, boolean served, String versionName) {
        V1CustomResourceDefinition item = new V1CustomResourceDefinition();
        V1ObjectMeta meta = new V1ObjectMeta();
        meta.setName(name);
        item.setMetadata(meta);
        V1CustomResourceDefinitionSpec spec = new V1CustomResourceDefinitionSpec();
        V1CustomResourceDefinitionVersion v = new V1CustomResourceDefinitionVersion();
        v.setName(versionName);
        v.setServed(served);
        spec.setVersions(List.of(v));
        item.setSpec(spec);
        return item;
    }
}
