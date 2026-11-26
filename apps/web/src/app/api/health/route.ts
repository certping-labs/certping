// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { NextResponse } from "next/server";

export function GET() {
  return NextResponse.json({ ok: true });
}
