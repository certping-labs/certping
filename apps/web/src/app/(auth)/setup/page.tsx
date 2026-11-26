// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import type { Metadata } from "next";
import React from "react";

import { privateRobots } from "@/lib/seo-metadata";
import { SetupForm } from "./setup-form";

export const metadata: Metadata = {
  title: "First-run setup",
  robots: privateRobots,
};

export default function SetupPage() {
  return <SetupForm />;
}
