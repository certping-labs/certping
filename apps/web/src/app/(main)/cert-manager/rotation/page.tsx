// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import React from "react";

import { RotationPage } from "@/components/cert-manager/rotation/rotation-page";
import { privateRobots } from "@/lib/seo-metadata";

export const metadata: Metadata = {
  title: "Rotation",
  robots: privateRobots,
};

export default function CertificateRotationPage() {
  return <RotationPage />;
}
