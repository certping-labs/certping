# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0

output "public_ip" {
  description = "Point your domain's A record here."
  value       = azurerm_public_ip.this.ip_address
}

output "url" {
  description = "Where CertPing answers once the VM has finished installing (about 10 minutes)."
  value       = "https://${local.domain}"
}

output "ssh" {
  description = "SSH command, when allowed_ssh_cidr is set."
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.this.ip_address}"
}

output "first_login" {
  description = "How to read the first admin's generated password."
  value       = "Sign in at the url output as admin. Read the first password on the VM with: sudo grep '^BOOTSTRAP_SUPER_ADMIN_PASSWORD=' /var/lib/docker/certping/.env (you choose a new one at the first sign-in)."
}
