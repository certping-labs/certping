// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

// Date assertions are written for UTC; pin it so results do not depend on the machine zone.
process.env.TZ = "UTC";
const sharedConfig = {
  roots: ["<rootDir>/src"],
  collectCoverageFrom: [
    "<rootDir>/src/**/*.{ts,tsx}",
    "!<rootDir>/src/**/*.d.ts",
    "!<rootDir>/src/test/**",
  ],
  coveragePathIgnorePatterns: [
    "<rootDir>/src/components/ui/",
    "<rootDir>/src/lib/api.ts",
    "<rootDir>/src/providers/react-query.tsx",
  ],
  coverageThreshold: {
    global: {
      statements: 85,
      branches: 85,
      functions: 85,
      lines: 85,
    },
  },
  transform: {
    "^.+\\.(m?[tj]sx?)$": ["@swc/jest"],
  },
  moduleNameMapper: {
    "\\.(svg)$": "<rootDir>/src/test/file-mock.ts",
    "\\.(css|scss|sass)$": "<rootDir>/src/test/style-mock.ts",
    "^@/(.*)$": "<rootDir>/src/$1",
  },
  testPathIgnorePatterns: ["/node_modules/", "/.next/"],
  transformIgnorePatterns: [],
  clearMocks: true,
  restoreMocks: true,
};

module.exports = {
  projects: [
    {
      ...sharedConfig,
      displayName: "node",
      testEnvironment: "node",
      setupFiles: ["<rootDir>/src/test/setup.node.ts"],
      testMatch: ["<rootDir>/src/**/*.test.ts"],
    },
    {
      ...sharedConfig,
      displayName: "jsdom",
      testEnvironment: "jsdom",
      setupFiles: ["<rootDir>/src/test/setup.node.ts"],
      setupFilesAfterEnv: ["<rootDir>/src/test/setup.dom.ts"],
      testMatch: [
        "<rootDir>/src/**/*.test.tsx",
        "<rootDir>/src/**/*.dom.test.ts",
      ],
    },
  ],
};
