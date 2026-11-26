# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

variable "subscription_id" {
  description = "Azure subscription to deploy into."
  type        = string
}

variable "name" {
  description = "Short name used in resource names."
  type        = string
  default     = "certping"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus2"
}

variable "dns_label" {
  description = "DNS label for the public IP: <label>.<region>.cloudapp.azure.com. Must be unique in the region."
  type        = string
}

variable "domain" {
  description = "Your own DNS name for CertPing (point an A record at the public IP). Empty uses the Azure DNS name."
  type        = string
  default     = ""
}

variable "vm_size" {
  description = "VM size. 2 vCPU and 8 GB is comfortable for thousands of certificates."
  type        = string
  default     = "Standard_B2ms"
}

variable "data_disk_size_gb" {
  description = "Size of the data disk holding the Docker volumes."
  type        = number
  default     = 64
}

variable "admin_username" {
  description = "Linux admin user."
  type        = string
  default     = "certping"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for the admin user."
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to reach SSH, for example your office IP /32. Empty closes SSH (use Azure Bastion or serial console)."
  type        = string
  default     = ""
}

variable "repo_url" {
  description = "Git repository with the CertPing deploy kit."
  type        = string
  default     = "https://github.com/certping-labs/certping.git"
}

variable "git_ref" {
  description = "Tag or branch to install."
  type        = string
  default     = "main"
}

variable "enable_backup" {
  description = "Nightly Azure VM backups, kept 14 days."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Extra tags for every resource."
  type        = map(string)
  default     = {}
}
