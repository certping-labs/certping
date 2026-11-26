// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

package com.certping.agent.kubernetes;

import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.ApiextensionsV1Api;
import io.kubernetes.client.openapi.apis.AppsV1Api;
import io.kubernetes.client.openapi.apis.BatchV1Api;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.apis.CustomObjectsApi;
import io.kubernetes.client.openapi.apis.NetworkingV1Api;
import io.kubernetes.client.openapi.models.V1APIResourceList;
import io.kubernetes.client.openapi.models.V1CronJobList;
import io.kubernetes.client.openapi.models.V1CustomResourceDefinitionList;
import io.kubernetes.client.openapi.models.V1DaemonSetList;
import io.kubernetes.client.openapi.models.V1DeleteOptions;
import io.kubernetes.client.openapi.models.V1DeploymentList;
import io.kubernetes.client.openapi.models.V1IngressList;
import io.kubernetes.client.openapi.models.V1JobList;
import io.kubernetes.client.openapi.models.V1NamespaceList;
import io.kubernetes.client.openapi.models.V1PodList;
import io.kubernetes.client.openapi.models.V1ReplicaSetList;
import io.kubernetes.client.openapi.models.V1Secret;
import io.kubernetes.client.openapi.models.V1SecretList;
import io.kubernetes.client.openapi.models.V1ServiceList;
import io.kubernetes.client.openapi.models.V1StatefulSetList;
import io.kubernetes.client.openapi.models.V1Status;

/**
 * The Kubernetes calls the agent makes, as plain methods over the current client-java request
 * builders. The agent passes only a few options (continue token, page size, dry run, field
 * manager); keeping them as arguments gives one place to adapt when the client changes again and
 * lets tests mock the calls directly.
 */
public final class KubeApis {

    /** Field selector that limits Secret lists to TLS Secrets. */
    public static final String TLS_SECRET_FIELD_SELECTOR = "type=kubernetes.io/tls";

    private KubeApis() {
    }

    /** Core API: namespaces, Secrets, Services, Pods. */
    public static class Core {
        private final CoreV1Api api;

        public Core(ApiClient client) {
            this(new CoreV1Api(client));
        }

        public Core(CoreV1Api api) {
            this.api = api;
        }

        public ApiClient getApiClient() {
            return api.getApiClient();
        }

        public V1NamespaceList listNamespaces(String continueToken, Integer limit) throws ApiException {
            return api.listNamespace()._continue(continueToken).limit(limit).execute();
        }

        /**
         * Lists only TLS Secrets ({@code type=kubernetes.io/tls}) in a namespace. The API server
         * applies the filter, so Opaque Secrets (passwords, tokens, keys) are never sent to the agent.
         */
        public V1SecretList listSecrets(String namespace, String continueToken, Integer limit) throws ApiException {
            return api.listNamespacedSecret(namespace)
                    .fieldSelector(TLS_SECRET_FIELD_SELECTOR)
                    ._continue(continueToken)
                    .limit(limit)
                    .execute();
        }

        public V1ServiceList listServices(String namespace, String continueToken, Integer limit) throws ApiException {
            return api.listNamespacedService(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1PodList listPods(String namespace, String continueToken, Integer limit) throws ApiException {
            return api.listNamespacedPod(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1Secret readSecret(String name, String namespace) throws ApiException {
            return api.readNamespacedSecret(name, namespace).execute();
        }

        public V1Secret createSecret(String namespace, V1Secret body, String dryRun, String fieldManager)
                throws ApiException {
            return api.createNamespacedSecret(namespace, body).dryRun(dryRun).fieldManager(fieldManager).execute();
        }

        public V1Secret replaceSecret(String name, String namespace, V1Secret body, String dryRun,
                                      String fieldManager) throws ApiException {
            return api.replaceNamespacedSecret(name, namespace, body).dryRun(dryRun).fieldManager(fieldManager)
                    .execute();
        }

        public V1Status deleteSecret(String name, String namespace) throws ApiException {
            return api.deleteNamespacedSecret(name, namespace).body(new V1DeleteOptions()).execute();
        }
    }

    /** Ingresses. */
    public static class Networking {
        private final NetworkingV1Api api;

        public Networking(ApiClient client) {
            this.api = new NetworkingV1Api(client);
        }

        public V1IngressList listIngresses(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedIngress(namespace)._continue(continueToken).limit(limit).execute();
        }
    }

    /** Deployments, ReplicaSets, StatefulSets, DaemonSets. */
    public static class Apps {
        private final AppsV1Api api;

        public Apps(ApiClient client) {
            this.api = new AppsV1Api(client);
        }

        public V1DeploymentList listDeployments(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedDeployment(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1ReplicaSetList listReplicaSets(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedReplicaSet(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1StatefulSetList listStatefulSets(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedStatefulSet(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1DaemonSetList listDaemonSets(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedDaemonSet(namespace)._continue(continueToken).limit(limit).execute();
        }
    }

    /** Jobs and CronJobs. */
    public static class Batch {
        private final BatchV1Api api;

        public Batch(ApiClient client) {
            this.api = new BatchV1Api(client);
        }

        public V1JobList listJobs(String namespace, String continueToken, Integer limit) throws ApiException {
            return api.listNamespacedJob(namespace)._continue(continueToken).limit(limit).execute();
        }

        public V1CronJobList listCronJobs(String namespace, String continueToken, Integer limit)
                throws ApiException {
            return api.listNamespacedCronJob(namespace)._continue(continueToken).limit(limit).execute();
        }
    }

    /** CustomResourceDefinitions. */
    public static class ApiExtensions {
        private final ApiextensionsV1Api api;

        public ApiExtensions(ApiClient client) {
            this.api = new ApiextensionsV1Api(client);
        }

        public V1CustomResourceDefinitionList listCustomResourceDefinitions(String continueToken, Integer limit)
                throws ApiException {
            return api.listCustomResourceDefinition()._continue(continueToken).limit(limit).execute();
        }
    }

    /** Custom resources such as cert-manager Certificates or Gateway API objects. */
    public static class CustomObjects {
        private final CustomObjectsApi api;

        public CustomObjects(ApiClient client) {
            this.api = new CustomObjectsApi(client);
        }

        public Object listNamespaced(String group, String version, String namespace, String plural,
                                     String continueToken, Integer limit) throws ApiException {
            return api.listNamespacedCustomObject(group, version, namespace, plural)._continue(continueToken)
                    .limit(limit).execute();
        }

        /** API discovery for one group version; readable by any authenticated identity. */
        public V1APIResourceList listApiResources(String group, String version) throws ApiException {
            return api.getAPIResources(group, version).execute();
        }
    }
}
