// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import localFont from "next/font/local";

export const certpingSans = localFont({
  src: "./fonts/PlusJakartaSans-Variable.ttf",
  variable: "--font-certping-sans",
  display: "swap",
  weight: "200 800",
});

export const certpingMono = localFont({
  src: "./fonts/GeistMonoVF.woff",
  variable: "--font-certping-mono",
  display: "swap",
  weight: "100 900",
});

export const landingSans = localFont({
  src: "./fonts/GeistVF.woff",
  variable: "--font-landing-sans",
  display: "swap",
  weight: "100 900",
});
