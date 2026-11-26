// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { OBJECT_URL_REVOKE_DELAY_MS } from "@/lib/download";

import type {
  CbomDocument,
  PqcReadinessCertificate,
  PqcReadinessReport,
} from "@/types/cbom-pqc";
import type { SpringPage } from "@/types/pagination";

jest.mock("@/components/ui/page-header", () => ({
  PageHeader: ({
    title,
    subtitle,
    actions,
  }: {
    title: string;
    subtitle?: string;
    actions?: React.ReactNode;
  }) => (
    <div>
      <h1>{title}</h1>
      {subtitle ? <p>{subtitle}</p> : null}
      {actions}
    </div>
  ),
}));

jest.mock("@/components/common/metric-card", () => ({
  MetricStrip: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  MetricCard: ({
    title,
    value,
    isLoading,
  }: {
    title: string;
    value: string | number;
    isLoading?: boolean;
  }) => (
    <div data-testid="metric-card">
      <span>{isLoading ? "…" : title}</span>
      <span>{value}</span>
    </div>
  ),
}));

jest.mock("@/components/ui/custom-table", () => ({
  CustomTable: ({
    data,
    emptyTableMsg,
  }: {
    data: Array<{
      commonName?: string;
      keyAlgorithm?: string;
      remediationAdvice?: string;
    }>;
    emptyTableMsg?: string;
  }) => (
    <div>
      {data.length === 0 ? (
        <p>{emptyTableMsg}</p>
      ) : (
        data.map((certificate) => (
          <article key={certificate.commonName}>
            <h3>{certificate.commonName}</h3>
            <p>{certificate.keyAlgorithm}</p>
            <p>{certificate.remediationAdvice}</p>
          </article>
        ))
      )}
    </div>
  ),
}));

const invalidateQueries = jest.fn();

jest.mock("@tanstack/react-query", () => ({
  ...jest.requireActual("@tanstack/react-query"),
  useQueryClient: () => ({ invalidateQueries }),
}));

jest.mock("@/hooks/use-cbom-pqc-dashboard", () => ({
  cbomPqcDashboardKeys: { pqcReadiness: ["cert-manager", "pqc-readiness"] },
  useCbomDownload: jest.fn(),
  usePqcReadinessReport: jest.fn(),
  usePqcReadinessCertificates: jest.fn(),
}));

import { CbomPqcDashboard } from "@/components/cert-manager/cbom-pqc-dashboard";
import {
  useCbomDownload,
  usePqcReadinessCertificates,
  usePqcReadinessReport,
} from "@/hooks/use-cbom-pqc-dashboard";

const mockUseCbomDownload = useCbomDownload as jest.MockedFunction<
  typeof useCbomDownload
>;
const mockUsePqcReadinessReport = usePqcReadinessReport as jest.MockedFunction<
  typeof usePqcReadinessReport
>;
const mockUsePqcReadinessCertificates =
  usePqcReadinessCertificates as jest.MockedFunction<
    typeof usePqcReadinessCertificates
  >;

type QueryState<TData> = {
  data?: TData;
  isLoading: boolean;
  isPending: boolean;
  isFetching: boolean;
  isError: boolean;
  refetch: jest.Mock;
};

type MutationState<TData> = {
  data?: TData;
  isPending: boolean;
  isError: boolean;
  mutate: jest.Mock;
};

const cbomDocument: CbomDocument = {
  text: '{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.6"\n}',
};

const readinessReport: PqcReadinessReport = {
  summary: {
    totalCertificates: 3,
    pqcCompliant: 1,
    deprecated2030: 1,
    disallowed2035: 1,
    unknown: 0,
    highHndlRisk: 1,
  },
  algorithms: [
    {
      publicKeyAlgorithm: "RSA",
      keySize: 4096,
      curve: null,
      quantumStatus: "DISALLOWED_2035",
      deprecationYear: null,
      disallowedYear: 2035,
      certificates: 1,
    },
  ],
};

const certificate: PqcReadinessCertificate = {
  certificateId: null,
  certificateXref: "cert-10",
  commonName: "api.example.com",
  keyAlgorithm: "RSA",
  keySize: 4096,
  curve: "",
  signatureAlgorithm: "SHA256withRSA",
  quantumStatus: "DISALLOWED_2035",
  hndlRisk: "HIGH",
  deprecationYear: null,
  disallowedYear: 2035,
  complianceRef: "NIST IR 8547",
  remediationAdvice: "Migrate this key exchange certificate first.",
};

const certificatePage = {
  content: [certificate],
  totalElements: 1,
  totalPages: 1,
  size: 15,
  number: 0,
} as SpringPage<PqcReadinessCertificate>;

describe("CbomPqcDashboard", () => {
  const originalCreateObjectUrl = URL.createObjectURL;
  const originalRevokeObjectUrl = URL.revokeObjectURL;

  beforeEach(() => {
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>() as unknown as ReturnType<
        typeof useCbomDownload
      >,
    );
    mockUsePqcReadinessReport.mockReturnValue(
      createQuery(readinessReport) as unknown as ReturnType<
        typeof usePqcReadinessReport
      >,
    );
    mockUsePqcReadinessCertificates.mockReturnValue(
      createQuery(certificatePage) as unknown as ReturnType<
        typeof usePqcReadinessCertificates
      >,
    );
    URL.createObjectURL = jest.fn(() => "blob:cbom");
    URL.revokeObjectURL = jest.fn();
  });

  afterEach(() => {
    URL.createObjectURL = originalCreateObjectUrl;
    URL.revokeObjectURL = originalRevokeObjectUrl;
  });

  it("renders cryptography dashboard summary content", () => {
    render(<CbomPqcDashboard />);

    expect(
      screen.getByRole("heading", { name: "PQC readiness" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Total certificates")).toHaveLength(2);
    expect(screen.getAllByText("PQC compliant").length).toBeGreaterThan(0);
    expect(
      screen.getByText("Certificate distribution timeline"),
    ).toBeInTheDocument();
    expect(screen.getByText("Algorithm status")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Export CBOM" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "View JSON" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/3 certificates · spec 1.6/i)).toBeInTheDocument();
    expect(screen.getByText("api.example.com")).toBeInTheDocument();
  });

  it("does not request the CBOM document on page load", () => {
    const mutate = jest.fn();
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({ mutate }) as unknown as ReturnType<
        typeof useCbomDownload
      >,
    );

    render(<CbomPqcDashboard />);

    expect(mutate).not.toHaveBeenCalled();
  });

  it("refreshes every readiness query, not the CBOM", async () => {
    const user = userEvent.setup();
    const mutate = jest.fn();
    invalidateQueries.mockClear();
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({ mutate }) as unknown as ReturnType<
        typeof useCbomDownload
      >,
    );

    render(<CbomPqcDashboard />);

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(invalidateQueries).toHaveBeenCalledWith({
      queryKey: ["cert-manager", "pqc-readiness"],
    });
    expect(mutate).not.toHaveBeenCalled();
  });

  it("requests the inventory page from the server with the selected status", async () => {
    const user = userEvent.setup();

    render(<CbomPqcDashboard />);

    expect(mockUsePqcReadinessCertificates).toHaveBeenLastCalledWith({
      page: 0,
      size: 15,
    });

    await user.click(
      screen.getByRole("button", { name: "Review affected certificates" }),
    );

    expect(mockUsePqcReadinessCertificates).toHaveBeenLastCalledWith({
      quantumStatus: "DISALLOWED_2035",
      page: 0,
      size: 15,
    });
  });

  it("fetches the CBOM document only when the export is requested", async () => {
    jest.useFakeTimers();
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    const clickSpy = jest
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation();
    const mutate = jest.fn(
      (_: undefined, options: { onSuccess: (doc: CbomDocument) => void }) =>
        options.onSuccess(cbomDocument),
    );
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({ mutate }) as unknown as ReturnType<
        typeof useCbomDownload
      >,
    );

    render(<CbomPqcDashboard />);

    expect(mutate).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Export CBOM" }));

    expect(mutate).toHaveBeenCalledTimes(1);
    expect(URL.createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(clickSpy).toHaveBeenCalled();
    act(() => {
      jest.advanceTimersByTime(OBJECT_URL_REVOKE_DELAY_MS);
    });
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:cbom");

    clickSpy.mockRestore();
    jest.useRealTimers();
  });

  it("fetches the CBOM document when the JSON view is opened", async () => {
    const user = userEvent.setup();
    const mutate = jest.fn(
      (_: undefined, options: { onSuccess: (doc: CbomDocument) => void }) =>
        options.onSuccess(cbomDocument),
    );
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({ mutate }) as unknown as ReturnType<
        typeof useCbomDownload
      >,
    );

    render(<CbomPqcDashboard />);

    await user.click(screen.getByRole("button", { name: "View JSON" }));

    expect(mutate).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("heading", { name: "CBOM JSON payload" }),
    ).toBeInTheDocument();
  });

  it("fetches a fresh CBOM document on every export", async () => {
    const user = userEvent.setup();
    const clickSpy = jest
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation();
    const mutate = jest.fn(
      (_: undefined, options: { onSuccess: (doc: CbomDocument) => void }) =>
        options.onSuccess(cbomDocument),
    );
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({
        data: cbomDocument,
        mutate,
      }) as unknown as ReturnType<typeof useCbomDownload>,
    );

    render(<CbomPqcDashboard />);

    await user.click(screen.getByRole("button", { name: "Export CBOM" }));
    await user.click(screen.getByRole("button", { name: "Export CBOM" }));

    expect(mutate).toHaveBeenCalledTimes(2);
    expect(clickSpy).toHaveBeenCalledTimes(2);

    clickSpy.mockRestore();
  });

  it("reports a CBOM download failure without hiding readiness data", () => {
    mockUseCbomDownload.mockReturnValue(
      createMutation<CbomDocument>({
        isError: true,
      }) as unknown as ReturnType<typeof useCbomDownload>,
    );

    render(<CbomPqcDashboard />);

    expect(
      screen.getByText(/CBOM document could not be generated/i),
    ).toBeInTheDocument();
    expect(screen.getByText("api.example.com")).toBeInTheDocument();
  });

  it("reports a PQC readiness failure independently", () => {
    mockUsePqcReadinessReport.mockReturnValue(
      createQuery<PqcReadinessReport>(undefined, {
        isError: true,
      }) as unknown as ReturnType<typeof usePqcReadinessReport>,
    );

    render(<CbomPqcDashboard />);

    expect(
      screen.getByText("Could not load PQC readiness data"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/readiness report is unavailable/i),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/certificate count unavailable/i),
    ).toBeInTheDocument();
  });
});

function createMutation<TData>(
  overrides: Partial<MutationState<TData>> = {},
): MutationState<TData> {
  return {
    data: undefined,
    isPending: false,
    isError: false,
    mutate: jest.fn(),
    ...overrides,
  };
}

function createQuery<TData>(
  data: TData | undefined,
  overrides: Partial<QueryState<TData>> = {},
): QueryState<TData> {
  return {
    data,
    isLoading: false,
    isPending: false,
    isFetching: false,
    isError: false,
    refetch: jest.fn(),
    ...overrides,
  };
}
