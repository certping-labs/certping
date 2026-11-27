// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React, { useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/navigation";
import { useFieldArray, useForm, type Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  WarningIcon,
  CircleNotchIcon,
  PlusIcon,
  TrashIcon,
} from "@phosphor-icons/react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useCaConnectors } from "@/hooks/machine-identity/use-ca-connectors";
import { useDeviceSources } from "@/hooks/machine-identity/use-device-sources";
import {
  KEY_STORAGE_PROVIDER_LABELS,
  PROFILE_ENROLLMENT_METHOD_LABELS,
  PROFILE_KIND_LABELS,
  PROFILE_LIFECYCLE_LABELS,
  PROFILE_PLATFORM_LABELS,
  PROFILE_SAN_TYPE_LABELS,
} from "@/lib/machine-identity/backend-display";
import type {
  CaConnectorResponse,
  CertificateProfileResponse,
  CreateCertificateProfileRequest,
  ProfileConfigurationInput,
  ProfileEnrollmentMethod,
  ProfileKind,
  ProfileLifecycleStatus,
} from "@/types/machine-identity-backend";

// The correlation marker CertPing writes into `description` on the backend;
// a user-entered value shaped like it is rejected server-side with a 400.
const CERTPING_MARKER = /\[certping:[^\]]*\]/i;
const OID_PATTERN = /^[0-2](\.[0-9]+)+$/;
const GUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_ASSIGNMENT_GROUPS = 20;

function parseGroupIds(value: string | undefined): string[] {
  return (value ?? "")
    .split(/[\s,]+/)
    .map((id) => id.trim())
    .filter(Boolean);
}

const TARGET_PLATFORMS = [
  "WINDOWS",
  "MACOS",
  "IOS",
  "IPADOS",
  "ANDROID",
  "LINUX",
] as const;
const PROFILE_KINDS: readonly ProfileKind[] = [
  "CERTIFICATE_ENROLLMENT",
  "TRUST_ANCHOR",
  "PROVISIONING_TEMPLATE",
  "ENROLLMENT_GROUP",
];
const ENROLLMENT_METHODS: readonly ProfileEnrollmentMethod[] = [
  "SCEP",
  "PKCS",
  "NONE",
];
const SAN_TYPES = ["EMAIL", "UPN", "DNS", "URI"] as const;
const WINDOWS_SCEP_KEY_USAGES = [
  "digitalSignature",
  "keyEncipherment",
] as const;
const WINDOWS_SCEP_KEY_SIZES = [2048, 4096] as const;
const KEY_STORAGE_PROVIDERS = [
  "useTpmKspOtherwiseUseSoftwareKsp",
  "useTpmKspOtherwiseFail",
  "usePassportForWorkKspOtherwiseFail",
  "useSoftwareKsp",
] as const;

const sanEntrySchema = z.object({
  type: z.enum(SAN_TYPES),
  format: z.string().trim().min(1, "A SAN template is required"),
});

const ekuEntrySchema = z.object({
  objectIdentifier: z
    .string()
    .trim()
    .regex(OID_PATTERN, "Must be a dotted OID, e.g. 1.3.6.1.5.5.7.3.2"),
  name: z.string().trim().optional(),
});

const configurationSchema = z.object({
  issuerXref: z.string().optional(),
  certificateScope: z.enum(["DEVICE", "USER"]).optional(),
  keyAlgorithm: z.enum(["RSA", "EC"]).optional(),
  keySize: z.coerce.number().int().optional(),
  curve: z.string().trim().optional(),
  signatureHash: z.string().trim().optional(),
  subjectNameFormat: z.string().trim().optional(),
  subjectAltNameFormats: z.array(sanEntrySchema).default([]),
  extendedKeyUsages: z.array(ekuEntrySchema).default([]),
  keyUsages: z.array(z.string()).default([]),
  validityValue: z.coerce.number().int().min(1).optional(),
  validityUnit: z.enum(["DAYS", "MONTHS", "YEARS"]).optional(),
  renewalWindowDays: z.coerce.number().int().min(0).optional(),
  keyExportable: z.boolean().nullable().optional(),
  renewalThresholdPercentage: z.coerce.number().int().min(1).max(99).optional(),
  keyStorageProvider: z.enum(KEY_STORAGE_PROVIDERS).optional(),
  assignmentGroupIds: z
    .string()
    .optional()
    .refine(
      (value) => parseGroupIds(value).every((id) => GUID_PATTERN.test(id)),
      "Enter Entra group object IDs (GUIDs), one per line",
    )
    .refine(
      (value) => parseGroupIds(value).length <= MAX_ASSIGNMENT_GROUPS,
      `At most ${MAX_ASSIGNMENT_GROUPS} groups`,
    ),
});

/**
 * Windows SCEP is the only native mutation target the backend implements
 * today; every other platform/method combination on an ACTIVE profile is
 * rejected with 501. The extra rules below mirror the server-side validator
 * so an operator sees the problem before submitting, not after.
 */
const profileSchema = z
  .object({
    name: z.string().trim().min(1, "A profile name is required").max(200),
    description: z
      .string()
      .trim()
      .max(1000)
      .refine(
        (value) => !CERTPING_MARKER.test(value),
        "This text is reserved for CertPing's internal correlation marker",
      )
      .optional(),
    sourceXref: z.string().min(1, "Select a device source"),
    lifecycleStatus: z.enum(["DRAFT", "ACTIVE", "ARCHIVED"]),
    targetPlatform: z.string().min(1, "Select a target platform"),
    targetVariant: z.string().trim().optional(),
    profileKind: z.enum(PROFILE_KINDS as [ProfileKind, ...ProfileKind[]]),
    enrollmentMethod: z.enum(
      ENROLLMENT_METHODS as [
        ProfileEnrollmentMethod,
        ...ProfileEnrollmentMethod[],
      ],
    ),
    configuration: configurationSchema,
  })
  .superRefine((values, context) => {
    const isActiveWindowsScep =
      values.lifecycleStatus === "ACTIVE" &&
      values.targetPlatform === "WINDOWS" &&
      values.profileKind === "CERTIFICATE_ENROLLMENT" &&
      values.enrollmentMethod === "SCEP";
    if (!isActiveWindowsScep) return;

    const cfg = values.configuration;
    const path = (field: string) => ["configuration", field];

    if (
      cfg.keyAlgorithm !== "RSA" ||
      !cfg.keySize ||
      !(WINDOWS_SCEP_KEY_SIZES as readonly number[]).includes(cfg.keySize)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: path("keySize"),
        message: "Windows SCEP requires RSA 2048 or 4096",
      });
    }
    if (!cfg.certificateScope) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: path("certificateScope"),
        message: "Select a certificate type",
      });
    }
    if (!cfg.subjectNameFormat) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: path("subjectNameFormat"),
        message: "A subject name format is required",
      });
    }
    if (cfg.keyUsages.length === 0) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: path("keyUsages"),
        message: "Select at least one key usage",
      });
    }
    if (
      cfg.keyStorageProvider &&
      cfg.keySize === 4096 &&
      cfg.keyStorageProvider !== "useSoftwareKsp"
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: path("keyStorageProvider"),
        message: "4096-bit keys are only supported with the software KSP",
      });
    }
  });

type ProfileFormValues = z.infer<typeof profileSchema>;

const DEFAULT_VALUES: ProfileFormValues = {
  name: "",
  description: "",
  sourceXref: "",
  lifecycleStatus: "DRAFT",
  targetPlatform: "WINDOWS",
  targetVariant: "STANDARD",
  profileKind: "CERTIFICATE_ENROLLMENT",
  enrollmentMethod: "SCEP",
  configuration: {
    certificateScope: "DEVICE",
    keyAlgorithm: "RSA",
    keySize: 2048,
    signatureHash: "SHA2",
    subjectNameFormat: "CN={{AAD_Device_ID}}",
    subjectAltNameFormats: [],
    extendedKeyUsages: [],
    keyUsages: ["digitalSignature", "keyEncipherment"],
    validityValue: 12,
    validityUnit: "MONTHS",
    renewalWindowDays: 20,
    keyExportable: false,
    renewalThresholdPercentage: 20,
    keyStorageProvider: "useTpmKspOtherwiseUseSoftwareKsp",
    assignmentGroupIds: "",
  },
};

function toFormValues(profile: CertificateProfileResponse): ProfileFormValues {
  const cfg = profile.configuration;
  const providerConfig = cfg?.providerConfig ?? {};
  return {
    name: profile.name,
    description: profile.description ?? "",
    sourceXref: profile.sourceXref,
    lifecycleStatus: profile.lifecycleStatus,
    targetPlatform: profile.targetPlatform,
    targetVariant: profile.targetVariant,
    profileKind: profile.profileKind,
    enrollmentMethod: profile.enrollmentMethod ?? "NONE",
    configuration: {
      issuerXref: cfg?.issuerXref ?? undefined,
      certificateScope: cfg?.certificateScope ?? undefined,
      keyAlgorithm: cfg?.keyAlgorithm ?? undefined,
      keySize: cfg?.keySize ?? undefined,
      curve: cfg?.curve ?? undefined,
      signatureHash: cfg?.signatureHash ?? undefined,
      subjectNameFormat: cfg?.subjectNameFormat ?? undefined,
      subjectAltNameFormats: cfg?.subjectAltNameFormats ?? [],
      extendedKeyUsages: cfg?.extendedKeyUsages ?? [],
      keyUsages: cfg?.keyUsages ?? [],
      validityValue: cfg?.validityValue ?? undefined,
      validityUnit: cfg?.validityUnit ?? undefined,
      renewalWindowDays: cfg?.renewalWindowDays ?? undefined,
      keyExportable: cfg?.keyExportable ?? undefined,
      renewalThresholdPercentage:
        typeof providerConfig.renewalThresholdPercentage === "number"
          ? providerConfig.renewalThresholdPercentage
          : undefined,
      keyStorageProvider:
        typeof providerConfig.keyStorageProvider === "string"
          ? (providerConfig.keyStorageProvider as ProfileFormValues["configuration"]["keyStorageProvider"])
          : undefined,
      assignmentGroupIds: Array.isArray(providerConfig.assignmentGroupIds)
        ? providerConfig.assignmentGroupIds.join("\n")
        : "",
    },
  };
}

/** Builds the `ProfileConfigurationInput` the backend expects from form state. */
function toConfigurationInput(
  configuration: ProfileFormValues["configuration"],
): ProfileConfigurationInput {
  const providerConfig: Record<string, unknown> = {};
  if (configuration.renewalThresholdPercentage !== undefined) {
    providerConfig.renewalThresholdPercentage =
      configuration.renewalThresholdPercentage;
  }
  if (configuration.keyStorageProvider) {
    providerConfig.keyStorageProvider = configuration.keyStorageProvider;
  }
  // Omitted when empty so assignments made in Intune are left alone.
  const groupIds = [
    ...new Set(
      parseGroupIds(configuration.assignmentGroupIds).map((id) =>
        id.toLowerCase(),
      ),
    ),
  ];
  if (groupIds.length > 0) {
    providerConfig.assignmentGroupIds = groupIds;
  }

  return {
    issuerXref: configuration.issuerXref || undefined,
    certificateScope: configuration.certificateScope,
    keyAlgorithm: configuration.keyAlgorithm,
    keySize: configuration.keySize,
    curve: configuration.curve || undefined,
    signatureHash: configuration.signatureHash || undefined,
    subjectNameFormat: configuration.subjectNameFormat || undefined,
    subjectAltNameFormats: configuration.subjectAltNameFormats,
    extendedKeyUsages: configuration.extendedKeyUsages,
    keyUsages: configuration.keyUsages,
    validityValue: configuration.validityValue,
    validityUnit: configuration.validityUnit,
    renewalWindowDays: configuration.renewalWindowDays,
    keyExportable: configuration.keyExportable ?? undefined,
    providerConfig,
  };
}

interface ProfileFormProps {
  profile?: CertificateProfileResponse;
  isSubmitting: boolean;
  /**
   * `confirmReissuance` is always `false` when creating; when editing an
   * ACTIVE, server-managed profile it reflects the required confirmation
   * checkbox below (the backend may reissue device certificates on update).
   */
  onSubmit: (
    input: CreateCertificateProfileRequest,
    confirmReissuance: boolean,
  ) => void;
  cancelHref: string;
}

export function ProfileForm({
  profile,
  isSubmitting,
  onSubmit,
  cancelHref,
}: ProfileFormProps) {
  const router = useRouter();
  const sourcesQuery = useDeviceSources();
  const caConnectorsQuery = useCaConnectors();

  const form = useForm<ProfileFormValues>({
    resolver: zodResolver(profileSchema) as Resolver<ProfileFormValues>,
    defaultValues: profile ? toFormValues(profile) : DEFAULT_VALUES,
  });

  const sanFields = useFieldArray({
    control: form.control,
    name: "configuration.subjectAltNameFormats",
  });
  const ekuFields = useFieldArray({
    control: form.control,
    name: "configuration.extendedKeyUsages",
  });

  const values = form.watch();
  const isWindowsScep =
    values.targetPlatform === "WINDOWS" &&
    values.profileKind === "CERTIFICATE_ENROLLMENT" &&
    values.enrollmentMethod === "SCEP";
  const isObservedOnly = profile?.controlMode === "OBSERVED_ONLY";

  // A profile can only be created against an existing native mutation path.
  // Snap key material back onto a Windows-legal value once SCEP is selected,
  // so a stale non-Windows value cannot ride along into an ACTIVE submit.
  useEffect(() => {
    if (!isWindowsScep) return;
    if (form.getValues("configuration.keyAlgorithm") !== "RSA") {
      form.setValue("configuration.keyAlgorithm", "RSA");
    }
    const keySize = form.getValues("configuration.keySize");
    if (
      !keySize ||
      !(WINDOWS_SCEP_KEY_SIZES as readonly number[]).includes(keySize)
    ) {
      form.setValue("configuration.keySize", 2048);
    }
  }, [isWindowsScep, form]);

  const [confirmReissuance, setConfirmReissuance] = useState(false);
  const requiresReissuanceConfirmation =
    Boolean(profile) &&
    profile?.controlMode === "CMS_MANAGED" &&
    values.lifecycleStatus === "ACTIVE";

  const handleSubmit = form.handleSubmit((submitted) => {
    onSubmit(
      {
        name: submitted.name,
        description: submitted.description?.trim() || undefined,
        sourceXref: submitted.sourceXref,
        lifecycleStatus: submitted.lifecycleStatus,
        targetPlatform: submitted.targetPlatform,
        targetVariant: submitted.targetVariant || undefined,
        profileKind: submitted.profileKind,
        enrollmentMethod: submitted.enrollmentMethod,
        configuration: toConfigurationInput(submitted.configuration),
      },
      confirmReissuance,
    );
  });

  if (isObservedOnly) {
    return (
      <div className="rounded-lg border border-dashed border-border bg-card p-6 text-sm text-muted-foreground">
        This profile was discovered from the provider and is read-only. It
        cannot be edited from CertPing.
      </div>
    );
  }

  return (
    <Form {...form}>
      <form onSubmit={handleSubmit} className="space-y-4">
        <IdentitySection
          form={form}
          sources={sourcesQuery.data ?? []}
          isEditing={Boolean(profile)}
        />
        <TargetSection form={form} isEditing={Boolean(profile)} />
        <KeyMaterialSection form={form} isWindowsScep={isWindowsScep} />
        <SubjectSection
          form={form}
          sanFields={sanFields}
          ekuFields={ekuFields}
          caConnectors={caConnectorsQuery.data ?? []}
        />
        <ValiditySection form={form} isWindowsScep={isWindowsScep} />
        {isWindowsScep ? <WindowsScepNotice /> : null}

        {requiresReissuanceConfirmation ? (
          <label className="flex items-start gap-2 rounded-lg border border-warning-100 bg-warning-50 p-4 text-sm text-warning-800">
            <Checkbox
              className="mt-0.5"
              checked={confirmReissuance}
              onCheckedChange={(checked) =>
                setConfirmReissuance(checked === true)
              }
            />
            This change may reissue certificates on affected devices. I
            understand and want to proceed.
          </label>
        ) : null}

        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            onClick={() => router.push(cancelHref)}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={
              isSubmitting ||
              (requiresReissuanceConfirmation && !confirmReissuance)
            }
          >
            {isSubmitting ? (
              <CircleNotchIcon
                className="size-4 animate-spin"
                aria-hidden="true"
              />
            ) : null}
            {profile ? "Save profile" : "Create profile"}
          </Button>
        </div>
      </form>
    </Form>
  );
}

type FormApi = ReturnType<typeof useForm<ProfileFormValues>>;

function IdentitySection({
  form,
  sources,
  isEditing,
}: {
  form: FormApi;
  sources: { sourceXref: string; displayName: string }[];
  isEditing: boolean;
}) {
  return (
    <FormSection
      title="Identity"
      description="How the profile is labeled, which device source it targets, and whether it is live."
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Profile name</FormLabel>
              <FormControl>
                <Input {...field} placeholder="Windows device authentication" />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="sourceXref"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Device source</FormLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={isEditing}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select a source" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {sources.map((source) => (
                    <SelectItem
                      key={source.sourceXref}
                      value={source.sourceXref}
                    >
                      {source.displayName}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {isEditing ? (
                <FormDescription>Fixed at creation.</FormDescription>
              ) : null}
              <FormMessage />
            </FormItem>
          )}
        />
      </div>
      <FormField
        control={form.control}
        name="description"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Description</FormLabel>
            <FormControl>
              <Textarea {...field} value={field.value ?? ""} rows={2} />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="lifecycleStatus"
        render={({ field }) => (
          <FormItem className="max-w-xs">
            <FormLabel>Lifecycle status</FormLabel>
            <Select value={field.value} onValueChange={field.onChange}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {(
                  Object.keys(
                    PROFILE_LIFECYCLE_LABELS,
                  ) as ProfileLifecycleStatus[]
                )
                  .filter((status) => status !== "ARCHIVED")
                  .map((status) => (
                    <SelectItem key={status} value={status}>
                      {PROFILE_LIFECYCLE_LABELS[status]}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
            <FormDescription>
              Draft profiles are saved without contacting the device source.
              Active profiles are dispatched immediately.
            </FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />
    </FormSection>
  );
}

function TargetSection({
  form,
  isEditing,
}: {
  form: FormApi;
  isEditing: boolean;
}) {
  return (
    <FormSection
      title="Target"
      description={
        isEditing
          ? "Fixed at creation - the backend's update contract does not accept changes to platform, kind, method, or variant. Create a new profile instead."
          : "Windows SCEP is the only combination the backend can currently deliver to a device; other combinations save as a draft."
      }
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <FormField
          control={form.control}
          name="targetPlatform"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Platform</FormLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={isEditing}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {TARGET_PLATFORMS.map((platform) => (
                    <SelectItem key={platform} value={platform}>
                      {PROFILE_PLATFORM_LABELS[platform] ?? platform}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="profileKind"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Profile kind</FormLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={isEditing}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {PROFILE_KINDS.map((kind) => (
                    <SelectItem key={kind} value={kind}>
                      {PROFILE_KIND_LABELS[kind] ?? kind}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="enrollmentMethod"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Enrollment method</FormLabel>
              <Select
                value={field.value}
                onValueChange={field.onChange}
                disabled={isEditing}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {ENROLLMENT_METHODS.map((method) => (
                    <SelectItem key={method} value={method}>
                      {PROFILE_ENROLLMENT_METHOD_LABELS[method] ?? method}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>
      <FormField
        control={form.control}
        name="targetVariant"
        render={({ field }) => (
          <FormItem className="max-w-xs">
            <FormLabel>Variant</FormLabel>
            <FormControl>
              <Input
                {...field}
                value={field.value ?? ""}
                placeholder="STANDARD"
                disabled={isEditing}
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />
    </FormSection>
  );
}

function KeyMaterialSection({
  form,
  isWindowsScep,
}: {
  form: FormApi;
  isWindowsScep: boolean;
}) {
  const keyAlgorithm = form.watch("configuration.keyAlgorithm");
  const keySize = form.watch("configuration.keySize");

  return (
    <FormSection
      title="Key material"
      description="Applied to every certificate this profile delivers."
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <FormField
          control={form.control}
          name="configuration.certificateScope"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Certificate type</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="DEVICE">Device certificate</SelectItem>
                  <SelectItem value="USER">User certificate</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="configuration.keyAlgorithm"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Algorithm</FormLabel>
              <Select
                value={field.value}
                disabled={isWindowsScep}
                onValueChange={field.onChange}
              >
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="RSA">RSA</SelectItem>
                  <SelectItem value="EC">EC</SelectItem>
                </SelectContent>
              </Select>
              {isWindowsScep ? (
                <FormDescription>Windows SCEP requires RSA.</FormDescription>
              ) : null}
              <FormMessage />
            </FormItem>
          )}
        />
        {keyAlgorithm === "EC" ? (
          <FormField
            control={form.control}
            name="configuration.curve"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Curve</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    value={field.value ?? ""}
                    placeholder="P-256"
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : (
          <FormField
            control={form.control}
            name="configuration.keySize"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Key size</FormLabel>
                {isWindowsScep ? (
                  <Select
                    value={field.value ? String(field.value) : undefined}
                    onValueChange={(value) => field.onChange(Number(value))}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {WINDOWS_SCEP_KEY_SIZES.map((size) => (
                        <SelectItem key={size} value={String(size)}>
                          {size} bits
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <FormControl>
                    <Input
                      type="number"
                      value={field.value ?? ""}
                      onChange={(event) =>
                        field.onChange(Number(event.target.value) || undefined)
                      }
                    />
                  </FormControl>
                )}
                <FormMessage />
              </FormItem>
            )}
          />
        )}
        <FormField
          control={form.control}
          name="configuration.signatureHash"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Signature hash</FormLabel>
              <FormControl>
                <Input
                  {...field}
                  value={field.value ?? ""}
                  placeholder="SHA2"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      {isWindowsScep ? (
        <div className="grid gap-4 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="configuration.keyStorageProvider"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Key storage provider</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger>
                      <SelectValue placeholder="Select" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {KEY_STORAGE_PROVIDERS.filter(
                      (provider) =>
                        keySize !== 4096 || provider === "useSoftwareKsp",
                    ).map((provider) => (
                      <SelectItem key={provider} value={provider}>
                        {KEY_STORAGE_PROVIDER_LABELS[provider] ?? provider}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="configuration.renewalThresholdPercentage"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Renewal threshold (%)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    min={1}
                    max={99}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(Number(event.target.value) || undefined)
                    }
                  />
                </FormControl>
                <FormDescription>
                  Percentage of remaining lifetime when renewal starts.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="configuration.assignmentGroupIds"
            render={({ field }) => (
              <FormItem className="sm:col-span-2">
                <FormLabel>Assign to Entra groups (object IDs)</FormLabel>
                <FormControl>
                  <Textarea
                    {...field}
                    value={field.value ?? ""}
                    rows={2}
                    placeholder="00000000-0000-0000-0000-000000000000"
                  />
                </FormControl>
                <FormDescription>
                  Optional, one per line. Assigning makes Intune deploy this
                  profile and its trusted root to these groups. Leave empty to
                  manage assignments in Intune.
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
      ) : (
        <FormField
          control={form.control}
          name="configuration.keyExportable"
          render={({ field }) => (
            <FormItem className="flex flex-col gap-2">
              <FormLabel>Private key exportable</FormLabel>
              <FormControl>
                <Switch
                  checked={field.value ?? false}
                  onCheckedChange={field.onChange}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      )}
    </FormSection>
  );
}

function SubjectSection({
  form,
  sanFields,
  ekuFields,
  caConnectors,
}: {
  form: FormApi;
  sanFields: ReturnType<
    typeof useFieldArray<
      ProfileFormValues,
      "configuration.subjectAltNameFormats"
    >
  >;
  ekuFields: ReturnType<
    typeof useFieldArray<ProfileFormValues, "configuration.extendedKeyUsages">
  >;
  caConnectors: CaConnectorResponse[];
}) {
  return (
    <FormSection
      title="Subject, SAN, and usage"
      description="Templates are expanded per device using variables from the source system, for example {{AAD_Device_ID}}."
    >
      <FormField
        control={form.control}
        name="configuration.issuerXref"
        render={({ field }) => (
          <FormItem className="max-w-sm">
            <FormLabel>Issuing CA</FormLabel>
            <Select value={field.value} onValueChange={field.onChange}>
              <FormControl>
                <SelectTrigger>
                  <SelectValue placeholder="Select a CA connector" />
                </SelectTrigger>
              </FormControl>
              <SelectContent>
                {caConnectors.map((connector) => (
                  <SelectItem
                    key={connector.connectorId}
                    value={connector.connectorId}
                  >
                    {connector.caProvider} · {connector.connectorId}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <FormMessage />
          </FormItem>
        )}
      />
      <FormField
        control={form.control}
        name="configuration.subjectNameFormat"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Subject name format</FormLabel>
            <FormControl>
              <Input
                {...field}
                value={field.value ?? ""}
                className="font-mono text-xs"
              />
            </FormControl>
            <FormMessage />
          </FormItem>
        )}
      />

      <FieldArraySection
        label="Subject alternative names"
        onAdd={() => sanFields.append({ type: "DNS", format: "" })}
      >
        {sanFields.fields.map((field, index) => (
          <div key={field.id} className="flex items-start gap-2">
            <FormField
              control={form.control}
              name={`configuration.subjectAltNameFormats.${index}.type`}
              render={({ field: typeField }) => (
                <FormItem className="w-28">
                  <Select
                    value={typeField.value}
                    onValueChange={typeField.onChange}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {SAN_TYPES.map((type) => (
                        <SelectItem key={type} value={type}>
                          {PROFILE_SAN_TYPE_LABELS[type] ?? type}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name={`configuration.subjectAltNameFormats.${index}.format`}
              render={({ field: formatField }) => (
                <FormItem className="flex-1">
                  <FormControl>
                    <Input {...formatField} className="font-mono text-xs" />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => sanFields.remove(index)}
              aria-label={`Remove SAN ${index + 1}`}
            >
              <TrashIcon className="size-4" aria-hidden="true" />
            </Button>
          </div>
        ))}
      </FieldArraySection>

      <FieldArraySection
        label="Extended key usages"
        onAdd={() => ekuFields.append({ objectIdentifier: "" })}
      >
        {ekuFields.fields.map((field, index) => (
          <div key={field.id} className="flex items-start gap-2">
            <FormField
              control={form.control}
              name={`configuration.extendedKeyUsages.${index}.objectIdentifier`}
              render={({ field: oidField }) => (
                <FormItem className="flex-1">
                  <FormControl>
                    <Input
                      {...oidField}
                      className="font-mono text-xs"
                      placeholder="1.3.6.1.5.5.7.3.2"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name={`configuration.extendedKeyUsages.${index}.name`}
              render={({ field: nameField }) => (
                <FormItem className="flex-1">
                  <FormControl>
                    <Input
                      {...nameField}
                      value={nameField.value ?? ""}
                      placeholder="Client authentication"
                    />
                  </FormControl>
                </FormItem>
              )}
            />
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => ekuFields.remove(index)}
              aria-label={`Remove EKU ${index + 1}`}
            >
              <TrashIcon className="size-4" aria-hidden="true" />
            </Button>
          </div>
        ))}
      </FieldArraySection>

      <FormField
        control={form.control}
        name="configuration.keyUsages"
        render={({ field }) => (
          <FormItem>
            <FormLabel>Key usages</FormLabel>
            <div className="flex flex-wrap gap-3">
              {WINDOWS_SCEP_KEY_USAGES.map((usage) => (
                <label key={usage} className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={field.value.includes(usage)}
                    onCheckedChange={(checked) =>
                      field.onChange(
                        checked
                          ? [...field.value, usage]
                          : field.value.filter((value) => value !== usage),
                      )
                    }
                  />
                  <span>
                    {usage === "digitalSignature"
                      ? "Digital signature"
                      : "Key encipherment"}
                  </span>
                </label>
              ))}
            </div>
            <FormMessage />
          </FormItem>
        )}
      />
    </FormSection>
  );
}

function ValiditySection({
  form,
  isWindowsScep,
}: {
  form: FormApi;
  isWindowsScep: boolean;
}) {
  return (
    <FormSection title="Validity and renewal">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <FormField
          control={form.control}
          name="configuration.validityValue"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Validity</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  min={1}
                  value={field.value ?? ""}
                  onChange={(event) =>
                    field.onChange(Number(event.target.value) || undefined)
                  }
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="configuration.validityUnit"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Unit</FormLabel>
              <Select value={field.value} onValueChange={field.onChange}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="DAYS">Days</SelectItem>
                  <SelectItem value="MONTHS">Months</SelectItem>
                  <SelectItem value="YEARS">Years</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        {!isWindowsScep ? (
          <FormField
            control={form.control}
            name="configuration.renewalWindowDays"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Renew before expiry (days)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    min={0}
                    value={field.value ?? ""}
                    onChange={(event) =>
                      field.onChange(Number(event.target.value) || undefined)
                    }
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        ) : null}
      </div>
    </FormSection>
  );
}

function WindowsScepNotice() {
  return (
    <section className="rounded-lg border border-warning-100 bg-warning-50 p-4 text-warning-800">
      <h2 className="flex items-center gap-2 text-sm font-semibold">
        <WarningIcon className="size-4" aria-hidden="true" />
        Windows SCEP validation applies
      </h2>
      <p className="mt-2 text-xs">
        Activating this profile dispatches a native SCEP profile create/update
        to the device source. The fields above are validated against Intune's
        Windows SCEP constraints before submitting; the backend re-validates and
        is the final authority.
      </p>
    </section>
  );
}

function FieldArraySection({
  label,
  onAdd,
  children,
}: {
  label: string;
  onAdd: () => void;
  children: ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <FormLabel>{label}</FormLabel>
        <Button type="button" variant="outline" size="sm" onClick={onAdd}>
          <PlusIcon className="size-4" aria-hidden="true" />
          Add
        </Button>
      </div>
      {children}
    </div>
  );
}

function FormSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-border bg-card">
      <header className="border-b border-border surface-muted px-4 py-2.5">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description ? (
          <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
        ) : null}
      </header>
      <div className="space-y-4 p-4">{children}</div>
    </section>
  );
}
