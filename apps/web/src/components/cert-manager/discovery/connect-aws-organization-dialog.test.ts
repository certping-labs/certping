// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import {
  buildAwsOrganizationConfig,
  splitList,
  type AwsOrganizationForm,
} from "./connect-aws-organization-dialog";

const base: AwsOrganizationForm = {
  name: "Prod org",
  authMode: "INSTANCE_PROFILE",
  roleArn: "",
  region: "",
  memberRoleName: "",
  externalId: "",
  accountIds: "",
  regions: "",
};

describe("buildAwsOrganizationConfig", () => {
  it("fills defaults and leaves out empty optional fields", () => {
    expect(buildAwsOrganizationConfig(base)).toEqual({
      authMode: "INSTANCE_PROFILE",
      region: "us-east-1",
      memberRoleName: "CertPingDiscoveryReadOnly",
    });
  });

  it("includes the hub role, external ID, accounts and regions when set", () => {
    expect(
      buildAwsOrganizationConfig({
        ...base,
        authMode: "ASSUME_ROLE",
        roleArn: " arn:aws:iam::111111111111:role/Hub ",
        externalId: "x-1",
        accountIds: "111111111111, 222222222222",
        regions: "us-east-1 eu-west-1",
      }),
    ).toEqual({
      authMode: "ASSUME_ROLE",
      region: "us-east-1",
      memberRoleName: "CertPingDiscoveryReadOnly",
      roleArn: "arn:aws:iam::111111111111:role/Hub",
      externalId: "x-1",
      accountIds: ["111111111111", "222222222222"],
      regions: ["us-east-1", "eu-west-1"],
    });
  });

  it("splits on commas and spaces", () => {
    expect(splitList(" a,b  c ,")).toEqual(["a", "b", "c"]);
  });
});
