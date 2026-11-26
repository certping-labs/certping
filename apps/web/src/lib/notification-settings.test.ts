// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import { AxiosError, AxiosHeaders } from "axios";

import { FEATURE_FLAGS } from "@/lib/feature-flags";
import {
  alwaysSentNotifications,
  isNotificationSettingsUnavailable,
  joinList,
  notificationCategories,
  notificationCategoryLabel,
  notificationChannels,
  notificationSettingsSaveError,
} from "@/lib/notification-settings";

const on =
  (...featureKeys: string[]) =>
  (featureKey: string) =>
    featureKeys.includes(featureKey);
const every = (featureKey: string) =>
  (Object.values(FEATURE_FLAGS) as string[]).includes(featureKey);
const descriptions = (isEnabled: (featureKey: string) => boolean) =>
  Object.fromEntries(
    notificationCategories(isEnabled).map(({ key, description }) => [
      key,
      description,
    ]),
  );
const alwaysSent = (isEnabled: (featureKey: string) => boolean) =>
  Object.fromEntries(
    alwaysSentNotifications(isEnabled).map(({ label, description }) => [
      label,
      description,
    ]),
  );

function httpError(status: number, data: unknown): AxiosError {
  const headers = new AxiosHeaders();
  return new AxiosError("Request failed", String(status), undefined, null, {
    status,
    statusText: "",
    headers,
    config: { headers },
    data,
  });
}

describe("notification settings", () => {
  it("names each category and never shows a raw key", () => {
    expect(notificationCategoryLabel("CERTIFICATE_ACTIVITY")).toBe(
      "Certificate activity",
    );
    expect(notificationCategoryLabel("NEW_ONE")).toBe("Another category");
  });

  it("joins a list the way a sentence does", () => {
    expect(joinList([], "or")).toBe("");
    expect(joinList(["issued"], "or")).toBe("issued");
    expect(joinList(["issued", "renewed"], "or")).toBe("issued or renewed");
    expect(joinList(["issued", "renewed", "deployed"], "or")).toBe(
      "issued, renewed or deployed",
    );
  });

  it("describes each category with every feature on, and only the categories the server serves", () => {
    expect(descriptions(every)).toEqual({
      CERTIFICATE_ACTIVITY: "A certificate was issued, renewed or deployed.",
      REPORTS: "Scan reports and activity digests. Findings stay in the app.",
    });
    expect(alwaysSent(every)).toEqual({
      "Security and account":
        "Password reset and sign-in emails and revoked certificates.",
      "Failures, expiry and action needed":
        "Failed issuance, renewal or deployment and expiring certificates.",
      "Service changes": "Features an administrator pauses or resumes.",
    });
    expect(notificationChannels(every)).toBe(
      "Each choice covers email and the Slack, Teams, PagerDuty and ServiceNow integrations.",
    );
  });

  it("names a certificate event only while its feature is on", () => {
    const issuance = FEATURE_FLAGS.CERTIFICATE_ISSUANCE;
    expect(descriptions(on(issuance)).CERTIFICATE_ACTIVITY).toBe(
      "A certificate was issued.",
    );
    expect(
      descriptions(on(issuance, FEATURE_FLAGS.CERTIFICATE_RENEWAL))
        .CERTIFICATE_ACTIVITY,
    ).toBe("A certificate was issued or renewed.");
    expect(
      descriptions(on(issuance, FEATURE_FLAGS.CERTIFICATE_DEPLOYMENT))
        .CERTIFICATE_ACTIVITY,
    ).toBe("A certificate was issued or deployed.");
    expect(descriptions(on()).CERTIFICATE_ACTIVITY).toBeUndefined();
  });

  it("hides a category whose features are all off", () => {
    expect(Object.keys(descriptions(on()))).toEqual(["REPORTS"]);
    expect(descriptions(every)).not.toHaveProperty("OTHER_CATEGORY");
  });

  it("drops what is always sent for features that are off, and stays a sentence", () => {
    expect(alwaysSent(on())).toEqual({
      "Security and account":
        "Password reset and sign-in emails and revoked certificates.",
      "Failures, expiry and action needed": "Expiring certificates.",
      "Service changes": "Features an administrator pauses or resumes.",
    });
    expect(
      alwaysSent(on(FEATURE_FLAGS.CERTIFICATE_ISSUANCE))[
        "Failures, expiry and action needed"
      ],
    ).toBe("Failed issuance and expiring certificates.");
    expect(
      alwaysSent(
        on(
          FEATURE_FLAGS.CERTIFICATE_ISSUANCE,
          FEATURE_FLAGS.CERTIFICATE_RENEWAL,
        ),
      )["Failures, expiry and action needed"],
    ).toBe("Failed issuance or renewal and expiring certificates.");
    expect(notificationChannels(on())).toBe("Each choice covers email.");
  });

  it("knows a closed feature by its 423", () => {
    expect(isNotificationSettingsUnavailable(httpError(423, {}))).toBe(true);
    expect(isNotificationSettingsUnavailable(httpError(403, {}))).toBe(false);
    expect(isNotificationSettingsUnavailable(new Error("x"))).toBe(false);
  });

  it("explains a failed save", () => {
    expect(notificationSettingsSaveError(httpError(423, {}))).toBe(
      "Notification settings aren't available. Ask your CertPing administrator.",
    );
    expect(
      notificationSettingsSaveError(
        httpError(400, { message: "A notification category is listed twice" }),
      ),
    ).toBe("Notification settings couldn't be saved. Please try again.");
    expect(notificationSettingsSaveError(httpError(400, {}))).toBe(
      "Notification settings couldn't be saved. Please try again.",
    );
    expect(notificationSettingsSaveError(httpError(500, {}))).toBe(
      "Notification settings couldn't be saved. Please try again.",
    );
  });
});
