// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  KUBERNETES_AUTH_METHODS,
  KUBERNETES_ALL_NAMESPACES,
  MANAGED_KUBERNETES_AUTH_METHODS,
  buildAllNamespacesSecretMap,
  buildNsSecretMapFromPairs,
  createKubernetesSecretDraft,
  generateDefaultTlsSecretName,
  getDefaultNamespaceSecretPairs,
  getKubernetesAuthMethodInstruction,
  getKubernetesAuthMethodLabel,
  getKubernetesAuthMethodSecretTemplate,
  isKubernetesSecretsTarget,
  normalizeNamespaceScope,
  parseCredentialNamespacesInput,
  parseKubernetesCredentialConfig,
  parseKubernetesNsSecretMap,
  parseNamespacesInput,
  parseSavedKubernetesDeploymentConfig,
  parseNamespaceSecretPairs,
  sanitizeDomainForSecretBase,
  sanitizeNamespaceSecretPairs,
  validateNamespace,
  validateSecretName,
} from "@/lib/credential-config-schemas/kubernetes-secrets";

describe("kubernetes credential config", () => {
  describe("namespace parsing and validation", () => {
    it("parses namespace input with trimming and de-duplication", () => {
      expect(parseCredentialNamespacesInput("alpha, alpha, beta")).toEqual([
        "alpha",
        "beta",
      ]);
    });

    it("returns all_namespaces literal when requested", () => {
      expect(parseCredentialNamespacesInput("all_namespaces")).toBe(
        KUBERNETES_ALL_NAMESPACES,
      );
    });

    it("drops empty namespace tokens and de-duplicates direct namespace parsing", () => {
      expect(parseNamespacesInput("prod, , qa,prod,\n, qa")).toEqual([
        "prod",
        "qa",
      ]);
    });

    it("validates namespace and secret names", () => {
      expect(validateNamespace("prod-api")).toBe("prod-api");
      expect(validateSecretName("tls.secret-1")).toBe("tls.secret-1");
    });

    it("throws on invalid namespace and secret names", () => {
      expect(() => validateNamespace("Prod")).toThrow(
        "Namespace must be lowercase and can include dashes",
      );
      expect(() => validateSecretName("Secret Name")).toThrow(
        "Secret name must be lowercase and can include dashes or dots",
      );
    });
  });

  describe("credential config parser", () => {
    it("parses direct config payloads", () => {
      expect(
        parseKubernetesCredentialConfig(
          JSON.stringify({
            authMethod: "AWS",
            clusterName: "prod-eks",
            namespaces: ["core"],
          }),
        ),
      ).toEqual({
        authMethod: "AWS",
        clusterName: "prod-eks",
        namespaces: ["core"],
      });
    });

    it("parses direct object config payloads", () => {
      expect(
        parseKubernetesCredentialConfig({
          authMethod: "AWS",
          clusterName: "prod-eks",
          namespaces: ["core"],
        }),
      ).toEqual({
        authMethod: "AWS",
        clusterName: "prod-eks",
        namespaces: ["core"],
      });
    });

    it("parses nested config payloads and rejects invalid shape", () => {
      expect(
        parseKubernetesCredentialConfig(
          JSON.stringify({
            config: {
              authMethod: "AZURE",
              clusterName: "prod-aks",
              namespaces: KUBERNETES_ALL_NAMESPACES,
            },
          }),
        ),
      ).toEqual({
        authMethod: "AZURE",
        clusterName: "prod-aks",
        namespaces: KUBERNETES_ALL_NAMESPACES,
      });

      expect(
        parseKubernetesCredentialConfig(JSON.stringify({ bad: true })),
      ).toBe(null);
      expect(parseKubernetesCredentialConfig({ bad: true })).toBe(null);
      expect(parseKubernetesCredentialConfig("{invalid-json")).toBe(null);
      expect(parseKubernetesCredentialConfig("   ")).toBe(null);
    });
  });

  describe("namespace-secret mapping", () => {
    it("sanitizes pair collection and removes duplicate namespaces", () => {
      expect(
        sanitizeNamespaceSecretPairs([
          { namespace: "prod", secretName: "first-tls" },
          { namespace: "prod", secretName: "ignored-tls" },
          { namespace: "qa", secretName: "qa-tls" },
        ]),
      ).toEqual([
        { namespace: "prod", secretName: "first-tls" },
        { namespace: "qa", secretName: "qa-tls" },
      ]);
    });

    it("parses namespace-secret lines and ignores duplicate namespaces", () => {
      expect(
        parseNamespaceSecretPairs("prod=prod-tls\nprod=ignored\nqa=qa-tls\n"),
      ).toEqual([
        { namespace: "prod", secretName: "prod-tls" },
        { namespace: "qa", secretName: "qa-tls" },
      ]);
    });

    it("parses explicit and all-namespaces maps", () => {
      expect(
        parseKubernetesNsSecretMap([{ prod: "prod-tls" }, { qa: "qa-tls" }]),
      ).toEqual({
        mapMode: "explicit",
        pairs: [
          { namespace: "prod", secretName: "prod-tls" },
          { namespace: "qa", secretName: "qa-tls" },
        ],
        allNamespacesSecret: "",
      });

      expect(
        parseKubernetesNsSecretMap({ [KUBERNETES_ALL_NAMESPACES]: "tls-all" }),
      ).toEqual({
        mapMode: "all_namespaces",
        pairs: [],
        allNamespacesSecret: "tls-all",
      });
    });

    it("handles invalid map entries for namespace-secret maps", () => {
      expect(
        parseKubernetesNsSecretMap([{ prod: "prod-tls" }, { qa: 12 }, null]),
      ).toEqual({
        mapMode: "explicit",
        pairs: [{ namespace: "prod", secretName: "prod-tls" }],
        allNamespacesSecret: "",
      });

      expect(parseKubernetesNsSecretMap({ bad: "shape" })).toBeNull();
      expect(() =>
        parseKubernetesNsSecretMap({
          [KUBERNETES_ALL_NAMESPACES]: "BAD SECRET",
        }),
      ).toThrow("Secret name must be lowercase and can include dashes or dots");
    });

    it("parses saved deployment config from object/string and invalid values", () => {
      expect(
        parseSavedKubernetesDeploymentConfig({
          nsMaps: [{ prod: "prod-tls" }],
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [{ namespace: "prod", secretName: "prod-tls" }],
        allNamespacesSecret: "",
      });

      expect(
        parseSavedKubernetesDeploymentConfig(
          JSON.stringify({
            nsMaps: { [KUBERNETES_ALL_NAMESPACES]: "global-tls" },
          }),
        ),
      ).toEqual({
        mapMode: "all_namespaces",
        pairs: [],
        allNamespacesSecret: "global-tls",
      });

      expect(parseSavedKubernetesDeploymentConfig("{bad-json")).toBeNull();
      expect(parseSavedKubernetesDeploymentConfig(null)).toBeNull();
      expect(
        parseSavedKubernetesDeploymentConfig({
          nsMaps: { [KUBERNETES_ALL_NAMESPACES]: "BAD SECRET" },
        }),
      ).toBeNull();
    });

    it("builds maps from pairs and all_namespaces values", () => {
      expect(
        buildNsSecretMapFromPairs([
          { namespace: "prod", secretName: "prod-tls" },
          { namespace: "qa", secretName: "qa-tls" },
        ]),
      ).toEqual([{ prod: "prod-tls" }, { qa: "qa-tls" }]);

      expect(buildAllNamespacesSecretMap("global-tls")).toEqual({
        [KUBERNETES_ALL_NAMESPACES]: "global-tls",
      });
    });

    it("throws when building all_namespaces map with invalid secret name", () => {
      expect(() => buildAllNamespacesSecretMap("INVALID SECRET")).toThrow(
        "Secret name must be lowercase and can include dashes or dots",
      );
    });
  });

  describe("secret-name generation and draft creation", () => {
    it("normalizes domain names and generates default tls names", () => {
      expect(sanitizeDomainForSecretBase("*.Demo.Example.Com")).toBe(
        "demo-example-com",
      );
      expect(generateDefaultTlsSecretName("app.example.com", "prod")).toBe(
        "app-example-com-prod-tls",
      );
      expect(generateDefaultTlsSecretName("app.example.com")).toBe(
        "app-example-com-tls",
      );
    });

    it("supports auth method labels/instructions/templates and kubernetes target check", () => {
      const labels = KUBERNETES_AUTH_METHODS.map((method) =>
        getKubernetesAuthMethodLabel(method),
      );
      const instructions = KUBERNETES_AUTH_METHODS.map((method) =>
        getKubernetesAuthMethodInstruction(method),
      );
      const templates = KUBERNETES_AUTH_METHODS.map((method) =>
        getKubernetesAuthMethodSecretTemplate(method),
      );

      expect(labels).toHaveLength(KUBERNETES_AUTH_METHODS.length);
      expect(instructions.every((value) => value.length > 0)).toBe(true);
      expect(
        templates.every((template) => template.trim().startsWith("{")),
      ).toBe(true);

      expect(isKubernetesSecretsTarget(" kubernetes_secrets ")).toBe(true);
      expect(isKubernetesSecretsTarget("aws")).toBe(false);
      expect(isKubernetesSecretsTarget()).toBe(false);
    });

    it("offers a generic service account token and in-cluster auth for pasted credentials", () => {
      // The server and agent accept SA_TOKEN for any distribution (k3s, kubeadm, OpenShift).
      expect(MANAGED_KUBERNETES_AUTH_METHODS).toEqual(
        expect.arrayContaining([
          "SA_TOKEN",
          "SA_INCLUSTER",
          "AWS",
          "AZURE",
          "GCP",
        ]),
      );
      expect(getKubernetesAuthMethodLabel("SA_TOKEN")).toBe(
        "Kubernetes (service account token)",
      );
    });

    it("normalizes namespace scope and computes default namespace-secret pairs", () => {
      expect(normalizeNamespaceScope(undefined)).toEqual({
        allNamespaces: false,
        namespaces: [],
      });
      expect(normalizeNamespaceScope(KUBERNETES_ALL_NAMESPACES)).toEqual({
        allNamespaces: true,
        namespaces: [],
      });
      expect(normalizeNamespaceScope(["prod", "qa"])).toEqual({
        allNamespaces: false,
        namespaces: ["prod", "qa"],
      });
      expect(
        getDefaultNamespaceSecretPairs("demo.example.com", ["prod", "qa"]),
      ).toEqual([
        { namespace: "prod", secretName: "demo-example-com-prod-tls" },
        { namespace: "qa", secretName: "demo-example-com-qa-tls" },
      ]);
    });

    it("creates default draft when no saved map exists", () => {
      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: ["prod", "qa"],
          supportsAllNamespaces: true,
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [
          { namespace: "prod", secretName: "demo-example-com-prod-tls" },
          { namespace: "qa", secretName: "demo-example-com-qa-tls" },
        ],
        allNamespacesSecret: "demo-example-com-tls",
      });
    });

    it("preserves all_namespaces drafts only when supported", () => {
      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: ["prod"],
          supportsAllNamespaces: true,
          savedNsSecretMap: { [KUBERNETES_ALL_NAMESPACES]: "global-tls" },
        }),
      ).toEqual({
        mapMode: "all_namespaces",
        pairs: [{ namespace: "prod", secretName: "demo-example-com-prod-tls" }],
        allNamespacesSecret: "global-tls",
      });

      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: ["prod"],
          supportsAllNamespaces: false,
          savedNsSecretMap: { [KUBERNETES_ALL_NAMESPACES]: "global-tls" },
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [{ namespace: "prod", secretName: "demo-example-com-prod-tls" }],
        allNamespacesSecret: "demo-example-com-tls",
      });
    });

    it("uses saved explicit pairs when no allowed namespaces are configured", () => {
      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: [],
          supportsAllNamespaces: true,
          savedNsSecretMap: [{ prod: "custom-prod" }, { qa: "custom-qa" }],
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [
          { namespace: "prod", secretName: "custom-prod" },
          { namespace: "qa", secretName: "custom-qa" },
        ],
        allNamespacesSecret: "demo-example-com-tls",
      });
    });

    it("merges saved explicit pairs with allowed namespaces and falls back to defaults", () => {
      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: ["prod", "qa"],
          supportsAllNamespaces: true,
          savedNsSecretMap: [{ prod: "custom-prod" }, { other: "unused" }],
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [
          { namespace: "prod", secretName: "custom-prod" },
          { namespace: "qa", secretName: "demo-example-com-qa-tls" },
        ],
        allNamespacesSecret: "demo-example-com-tls",
      });
    });

    it("falls back to defaults when saved namespace map is invalid", () => {
      expect(
        createKubernetesSecretDraft({
          domain: "demo.example.com",
          allowedNamespaces: ["prod"],
          supportsAllNamespaces: true,
          savedNsSecretMap: { [KUBERNETES_ALL_NAMESPACES]: "BAD SECRET" },
        }),
      ).toEqual({
        mapMode: "explicit",
        pairs: [{ namespace: "prod", secretName: "demo-example-com-prod-tls" }],
        allNamespacesSecret: "demo-example-com-tls",
      });
    });
  });
});
