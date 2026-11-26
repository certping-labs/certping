// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

import * as React from "react";
import Image from "next/image";
import {
  CheckIcon,
  CaretDownIcon,
  PlusIcon,
  MagnifyingGlassIcon,
  XIcon,
} from "@phosphor-icons/react/dist/ssr";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

export type Option = {
  label: string;
  value: string;
  icon?: string;
};

interface MultiSelectProps {
  options: Option[];
  selected: string[];
  onChange: (selected: string[]) => void;
  className?: string;
  placeholder?: string;
  side?: "top" | "bottom" | "left" | "right";
  action?: {
    label: string;
    onSelect: () => void;
  };
}

export function MultiSelect({
  options,
  selected,
  onChange,
  className,
  placeholder = "Select options...",
  side = "bottom",
  action,
}: MultiSelectProps) {
  const [open, setOpen] = React.useState(false);
  const listboxId = React.useId();
  const triggerRef = React.useRef<HTMLButtonElement>(null);
  const [popoverWidth, setPopoverWidth] = React.useState<number>();
  const [searchTerm, setSearchTerm] = React.useState("");
  const optionsByValue = React.useMemo(
    () =>
      new Map(
        options.map((option) => [
          option.value,
          { label: option.label, icon: option.icon },
        ]),
      ),
    [options],
  );

  const handleUnselect = (item: string) => {
    onChange(selected.filter((i) => i !== item));
  };

  const filteredOptions = React.useMemo(() => {
    const normalizedSearch = searchTerm.trim().toLowerCase();
    if (!normalizedSearch) {
      return options;
    }

    return options.filter((option) =>
      option.label.toLowerCase().includes(normalizedSearch),
    );
  }, [options, searchTerm]);

  React.useEffect(() => {
    if (!open) return;

    const updateWidth = () => {
      setPopoverWidth(triggerRef.current?.offsetWidth);
    };

    updateWidth();
    window.addEventListener("resize", updateWidth);
    return () => window.removeEventListener("resize", updateWidth);
  }, [open]);

  React.useEffect(() => {
    if (!open) {
      setSearchTerm("");
    }
  }, [open]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          ref={triggerRef}
          variant="outline"
          role="combobox"
          aria-expanded={open}
          aria-haspopup="listbox"
          aria-controls={listboxId}
          className={cn(
            "min-h-10 w-full min-w-0 justify-between overflow-hidden rounded-(--radius-control) border-[hsl(var(--control-border))] bg-[hsl(var(--control-bg))] px-1.5 py-1.5 text-left font-normal text-foreground hover:bg-[hsl(var(--control-bg))] active:scale-100",
            className,
          )}
        >
          <div className="flex min-w-0 flex-1 scrollbar-none flex-row gap-1 overflow-x-auto">
            {selected.length === 0 ? (
              <span className="text-muted-foreground">{placeholder}</span>
            ) : selected.length <= 3 ? (
              selected.map((item) => (
                <Badge
                  variant="secondary"
                  key={item}
                  className="max-w-56 min-w-0 gap-1 pr-1"
                >
                  {optionsByValue.get(item)?.icon ? (
                    <Image
                      src={optionsByValue.get(item)?.icon || "/assets/aws.svg"}
                      alt=""
                      width={12}
                      height={12}
                      className="mr-1 h-3 w-3 object-contain"
                    />
                  ) : null}
                  <span className="min-w-0 truncate">
                    {optionsByValue.get(item)?.label || item}
                  </span>
                  <span
                    role="button"
                    tabIndex={0}
                    aria-label={`Remove ${optionsByValue.get(item)?.label || item}`}
                    className="rounded-full p-0.5 text-muted-foreground outline-hidden transition-colors hover:bg-[hsl(var(--secondary-200))] hover:text-foreground focus-visible:ring-2 focus-visible:ring-brand focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                    onKeyDown={(event) => {
                      if (event.key !== "Enter" && event.key !== " ") {
                        return;
                      }
                      event.preventDefault();
                      event.stopPropagation();
                      handleUnselect(item);
                    }}
                    onMouseDown={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                    }}
                    onClick={(event) => {
                      event.preventDefault();
                      event.stopPropagation();
                      handleUnselect(item);
                    }}
                  >
                    <XIcon className="h-3 w-3 text-muted-foreground hover:text-foreground" />
                  </span>
                </Badge>
              ))
            ) : (
              <Badge variant="secondary" className="shrink-0">
                {selected.length} selected
              </Badge>
            )}
          </div>
          <CaretDownIcon className="mr-2 h-4 w-4 shrink-0 text-muted-foreground" />
        </Button>
      </PopoverTrigger>
      <PopoverContent
        align="start"
        side={side}
        sideOffset={8}
        collisionPadding={16}
        className="z-70 flex flex-col overflow-hidden p-0"
        style={{
          width: popoverWidth,
          maxHeight:
            "min(24rem, var(--radix-popover-content-available-height, 24rem))",
        }}
      >
        <div className="flex min-h-0 flex-1 flex-col bg-popover">
          <div className="relative shrink-0 border-b border-divider px-1.5 py-1.5">
            <MagnifyingGlassIcon className="pointer-events-none absolute top-1/2 left-4 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={searchTerm}
              onChange={(event) => setSearchTerm(event.target.value)}
              placeholder="Search options..."
              className="border-0 bg-transparent pl-9 hover:bg-transparent focus-visible:ring-0"
            />
          </div>
          <div
            id={listboxId}
            role="listbox"
            aria-multiselectable="true"
            className="max-h-64 min-h-0 flex-1 overflow-y-auto overscroll-contain p-1.5"
            onWheel={(e) => e.stopPropagation()}
          >
            {filteredOptions.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No options found.
              </div>
            ) : (
              <>
                {filteredOptions.length > 0 ? (
                  <button
                    type="button"
                    className="mb-1 flex w-full items-center gap-2 rounded-[10px] px-2.5 py-2 text-left text-sm font-medium transition-colors hover:bg-secondary"
                    onClick={() => {
                      const allValues = filteredOptions.map((o) => o.value);
                      const allSelected = allValues.every((v) =>
                        selected.includes(v),
                      );
                      if (allSelected) {
                        onChange(
                          selected.filter((v) => !allValues.includes(v)),
                        );
                      } else {
                        onChange([...new Set([...selected, ...allValues])]);
                      }
                    }}
                  >
                    <CheckIcon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        filteredOptions.every((o) => selected.includes(o.value))
                          ? "opacity-100"
                          : filteredOptions.some((o) =>
                                selected.includes(o.value),
                              )
                            ? "opacity-50"
                            : "opacity-0",
                      )}
                    />
                    <span>Select all</span>
                  </button>
                ) : null}
                {filteredOptions.map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    role="option"
                    aria-selected={selected.includes(option.value)}
                    className="flex w-full items-center gap-2 rounded-[10px] px-2.5 py-2 text-left text-sm transition-colors hover:bg-secondary"
                    onClick={() => {
                      onChange(
                        selected.includes(option.value)
                          ? selected.filter((item) => item !== option.value)
                          : [...selected, option.value],
                      );
                    }}
                  >
                    <CheckIcon
                      className={cn(
                        "h-4 w-4 shrink-0",
                        selected.includes(option.value)
                          ? "opacity-100"
                          : "opacity-0",
                      )}
                    />
                    {option.icon ? (
                      <Image
                        src={option.icon}
                        alt=""
                        width={14}
                        height={14}
                        className="h-3.5 w-3.5 object-contain"
                      />
                    ) : null}
                    <span className="truncate">{option.label}</span>
                  </button>
                ))}
              </>
            )}
          </div>
          {action ? (
            <button
              type="button"
              className="flex w-full shrink-0 items-center gap-2 border-t border-divider px-4 py-2.5 text-left text-sm font-medium text-primary transition-colors hover:bg-secondary"
              onClick={() => {
                setOpen(false);
                action.onSelect();
              }}
            >
              <PlusIcon className="h-4 w-4 shrink-0" />
              <span>{action.label}</span>
            </button>
          ) : null}
        </div>
      </PopoverContent>
    </Popover>
  );
}
