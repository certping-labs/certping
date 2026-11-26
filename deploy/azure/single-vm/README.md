# CertPing on a single Azure VM

The Docker Compose install on one Ubuntu VM, created with Terraform. No Azure Container Apps,
no message broker and no managed database: one VM, one data disk, one public IP.

What it creates: a resource group, a VNet and NSG (80 and 443 open, SSH only from the CIDR you
give), a static public IP with an Azure DNS name, an Ubuntu 24.04 VM, a separate Premium data disk
for the Docker volumes, and (by default) nightly VM backups kept 14 days.

```bash
cd deploy/azure/single-vm
terraform init
terraform apply \
  -var subscription_id=<subscription-id> \
  -var dns_label=acme-certping \
  -var git_ref=v0.0.1-beta \
  -var "admin_ssh_public_key=$(cat ~/.ssh/id_ed25519.pub)" \
  -var allowed_ssh_cidr=203.0.113.4/32
```

After about ten minutes CertPing answers at the `url` output with a Let's Encrypt certificate.
To use your own domain, set `-var domain=certping.example.com` and point its A record at the
`public_ip` output before the VM finishes installing.

First login: sign in as `admin`. SSH in and read the generated first password (the `first_login`
output shows the command); you choose a new one at the first sign-in.

Things to know:

- The data disk has `prevent_destroy`, so `terraform destroy` stops at it. Remove the lifecycle
  block if you want the data deleted.
- `.env` with the install's keys sits on the data disk next to the volumes, so rebuilding the VM
  keeps everything. Copy it somewhere safe as well.
- The VM takes the Compose kit from `repo_url` at `git_ref` and pulls the released images named
  by `CERTPING_VERSION` (the kit's default release). Pin `git_ref` to that release's tag, for
  example `-var git_ref=v0.0.1-beta`; the default `main` can be ahead of the released images.
- For high availability use the Helm chart on AKS with Azure Database for PostgreSQL and Key Vault.
