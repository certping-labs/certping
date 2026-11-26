// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

/**
 * A user agent in words: "Chrome 129 on macOS", "curl 8", or the raw string
 * when it names nothing known. Good enough to recognise a session, not to
 * fingerprint one.
 */

const BROWSERS: readonly { name: string; pattern: RegExp }[] = [
  // Order matters: Edge and Opera also say Chrome, Chrome also says Safari.
  { name: "Edge", pattern: /\bEdg(?:e|A|iOS)?\/(\d+)/ },
  { name: "Opera", pattern: /\bOPR\/(\d+)/ },
  { name: "Samsung Internet", pattern: /\bSamsungBrowser\/(\d+)/ },
  { name: "Firefox", pattern: /\b(?:Firefox|FxiOS)\/(\d+)/ },
  { name: "Chrome", pattern: /\b(?:Chrome|CriOS)\/(\d+)/ },
  { name: "Safari", pattern: /\bVersion\/(\d+)[\d.]*\s.*Safari\// },
];

const SYSTEMS: readonly { name: string; pattern: RegExp }[] = [
  { name: "iOS", pattern: /\b(?:iPhone|iPad|iPod)\b/ },
  { name: "Android", pattern: /\bAndroid\b/ },
  { name: "ChromeOS", pattern: /\bCrOS\b/ },
  { name: "Windows", pattern: /\bWindows\b/ },
  { name: "macOS", pattern: /\bMac OS X\b|\bMacintosh\b/ },
  { name: "Linux", pattern: /\bLinux\b/ },
];

// Command-line clients and SDKs name themselves first: "curl/8.4.0".
const TOOL = /^([A-Za-z][\w.-]*)\/(\d+)/;
const MAX_RAW_LENGTH = 120;

export const describeUserAgent = (userAgent: string): string => {
  const text = userAgent.trim();
  if (!text) {
    return "Unknown";
  }
  const browser = BROWSERS.find(({ pattern }) => pattern.test(text));
  const system = SYSTEMS.find(({ pattern }) => pattern.test(text));
  if (browser) {
    const version = browser.pattern.exec(text)?.[1];
    const name = version ? `${browser.name} ${version}` : browser.name;
    return system ? `${name} on ${system.name}` : name;
  }
  const tool = TOOL.exec(text);
  if (tool && tool[1] !== "Mozilla") {
    return `${tool[1]} ${tool[2]}`;
  }
  if (system) {
    return `Unknown browser on ${system.name}`;
  }
  return text.length > MAX_RAW_LENGTH
    ? `${text.slice(0, MAX_RAW_LENGTH)}…`
    : text;
};
