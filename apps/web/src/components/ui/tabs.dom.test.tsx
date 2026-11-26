// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

describe("Tabs", () => {
  it("renders a Material Glass segmented control with a sliding thumb by default", () => {
    render(
      <Tabs defaultValue="all">
        <TabsList aria-label="Credential type">
          <TabsTrigger value="all">All</TabsTrigger>
          <TabsTrigger value="dns">DNS</TabsTrigger>
        </TabsList>
      </Tabs>,
    );

    const list = screen.getByRole("tablist", { name: "Credential type" });
    expect(list).toHaveAttribute("data-variant", "segmented");
    expect(list).toHaveClass("rounded-full", "mg-segmented");
    expect(list.querySelector(".mg-thumb")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    expect(screen.getByRole("tab", { name: "All" })).toHaveClass(
      "h-8",
      "rounded-full",
      "data-[state=active]:text-foreground",
    );
  });

  it("gives every trigger the underline treatment when the list asks for it", async () => {
    render(
      <Tabs defaultValue="overview">
        <TabsList variant="underline" aria-label="Domain sections">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="dns">DNS</TabsTrigger>
        </TabsList>
        <TabsContent value="overview">Overview body</TabsContent>
        <TabsContent value="dns">DNS body</TabsContent>
      </Tabs>,
    );

    const list = screen.getByRole("tablist", { name: "Domain sections" });
    expect(list).toHaveAttribute("data-variant", "underline");
    expect(list).toHaveClass("border-b");

    const dns = screen.getByRole("tab", { name: "DNS" });
    expect(list.querySelector(".mg-tab-indicator")).toBeInTheDocument();
    expect(dns).not.toHaveClass("rounded-full");

    await userEvent.click(dns);
    expect(dns).toHaveAttribute("data-state", "active");
    expect(screen.getByText("DNS body")).toBeInTheDocument();
  });
});
