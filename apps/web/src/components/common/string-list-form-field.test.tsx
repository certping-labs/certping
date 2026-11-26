// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { StringListFormField } from "@/components/common/string-list-form-field";
import { Form } from "@/components/ui/form";

const schema = z
  .object({ k8sNamespaces: z.array(z.string()) })
  .superRefine((values, context) => {
    if (!values.k8sNamespaces.some((value) => value.trim())) {
      context.addIssue({
        code: "custom",
        path: ["k8sNamespaces"],
        message: "At least one namespace is required",
      });
    }
  });

function NamespacesHarness() {
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { k8sNamespaces: [] },
  });
  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(() => undefined)}>
        <StringListFormField
          form={form}
          name={"k8sNamespaces" as never}
          label="Namespaces"
          placeholder="prod"
          addLabel="Add namespace"
        />
        <button type="submit">Save</button>
      </form>
    </Form>
  );
}

describe("StringListFormField", () => {
  it("labels added rows and shows the list error instead of undefined", async () => {
    const user = userEvent.setup();
    render(<NamespacesHarness />);

    await user.click(screen.getByRole("button", { name: "Add namespace" }));
    expect(
      screen.getByRole("textbox", { name: "Namespaces 1" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Remove Namespaces 1" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText("At least one namespace is required"),
    ).toBeInTheDocument();
    expect(screen.queryByText("undefined")).not.toBeInTheDocument();
  });
});
