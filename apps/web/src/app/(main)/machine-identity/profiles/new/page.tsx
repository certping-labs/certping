// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

"use client";

import React from "react";
import { useRouter } from "next/navigation";

import { ProfileForm } from "@/components/machine-identity/profile-form";
import { PageHeader } from "@/components/ui/page-header";
import { useCreateCertificateProfile } from "@/hooks/machine-identity/use-certificate-profiles";

const PROFILES_HREF = "/machine-identity/profiles";

export default function NewCertificateProfilePage() {
  const router = useRouter();
  const createProfile = useCreateCertificateProfile();

  return (
    <div className="space-y-5 p-4 md:p-6">
      <PageHeader
        title="New certificate profile"
        breadcrumbs={[
          { label: "Machine Identity" },
          { label: "Profiles", href: PROFILES_HREF },
        ]}
        subtitle="Define what CertPing delivers to the devices this profile targets."
      />

      <ProfileForm
        isSubmitting={createProfile.isPending}
        cancelHref={PROFILES_HREF}
        onSubmit={(input) =>
          createProfile.mutate(input, {
            onSuccess: (profile) =>
              router.push(`${PROFILES_HREF}/${profile.profileXref}`),
          })
        }
      />
    </div>
  );
}
