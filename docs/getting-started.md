# Getting started

In this tutorial we run CertPing in one container, issue a certificate from Let's Encrypt's
staging environment, write it into a Kubernetes TLS secret, renew it and replace it, and set up
email. At the end you can run this and see a certificate that CertPing issued and will keep
renewing:

```console
$ kubectl -n app get secret app-example-com-tls -o jsonpath='{.data.tls\.crt}' \
    | base64 -d | openssl x509 -noout -subject -issuer
subject=CN=app.example.com
issuer=C=US, O=(STAGING) Let's Encrypt, CN=(STAGING) ...
```

Staging certificates are not trusted by browsers, and they do not count against Let's Encrypt's
production rate limits, which is what we want for a test. The last step switches to production.
Allow about 30 minutes.

You need:

- Docker and about 4 GB of free memory, on amd64 or arm64.
- A domain whose DNS is hosted at a provider CertPing supports. We use Cloudflare in the
  examples; the [list of providers](integrations.md#dns-providers) has the fields for the others.
- For step 6, a Kubernetes cluster that the machine running Docker can reach. You can skip that
  step and still do the rest.

If you have no domain or cluster and only want to see every flow work, run the
[end-to-end lab](../deploy/e2e-lab/README.md) instead. It brings its own CA, DNS server, k3s and
mailbox.

The commands below use the released image `ghcr.io/certping-labs/certping:0.0.1-beta`. To use
your own build instead, run `make images` in the repository and replace that image name with
`certping-allinone:dev` in every command.

## 1. Start CertPing with Let's Encrypt staging

If you already ran the quickstart from the README, remove that container and its volume first,
because the first admin's email address below is only read on a new volume:

```sh
docker rm -f certping
docker volume rm certping
```

Start the container. Put your own address in the two email settings: the first is the contact on
the ACME account, the second becomes the first admin's address, so alert emails in step 8 reach
you.

```sh
docker run -d --name certping \
  -p 80:80 -p 443:443 \
  -v certping:/var/lib/certping \
  -e CERTPING_URL=http://localhost \
  -e ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_EMAIL=you@example.com \
  -e BOOTSTRAP_SUPER_ADMIN_EMAIL=you@example.com \
  ghcr.io/certping-labs/certping:0.0.1-beta
until curl -fs -o /dev/null http://localhost/api/v1/deployment-info; do sleep 5; done; echo ready
```

The first start takes two to four minutes. The loop prints `ready` when the server answers. If
you want to watch it work, run `docker logs -f certping` in another terminal.

## 2. Sign in and change the password

Print the first sign-in details:

```sh
docker exec certping certping-admin
```

You should see something like this, with a random password:

```text
URL:      http://localhost
Username: admin
Password: 3vXk... (initial; changed at first sign-in)
Forgot a password? certping-admin reset-password <username or email>
```

Open http://localhost and sign in as `admin` with that password. CertPing takes you to
**Organization & Access**, tab **Your account**, with the password form open. Until you change
the password, the API refuses every other call with `403` and the code
`PASSWORD_CHANGE_REQUIRED`. The new password needs at least 12 characters, with an uppercase
letter, a lowercase letter, a number and one of `@$!%*?&`.

After you save it, the sidebar shows every page. You are working in an organization called
"My organization". CertPing created it with the first admin, and everything we add belongs to it.
The container also runs an agent that has already joined this organization, so there is nothing
to install before we issue a certificate. Open **Agents** in the sidebar to see it: it is tagged
**Bundled** and shows **Online**. [Concepts](architecture.md#concepts) explains organizations and agents.

## 3. Connect your DNS provider

CertPing proves to the CA that you control the domain with the ACME DNS-01 challenge. The agent
writes a TXT record at `_acme-challenge.<your domain>`, waits until the domain's own nameservers
return it, lets the CA check it, and deletes it. To do that it needs an API token for the DNS
provider.

In Cloudflare, create an API token with the permission Zone, DNS, Edit for your zone. Then, in
CertPing:

1. Open **Integrations**, tab **DNS Providers**, and select **Connect DNS provider**.
2. Pick **Cloudflare DNS** and enter the **Name** `cloudflare-example-com`.
3. Under **How does the agent get this secret?** choose **Paste the credential**.
4. Paste the token into **Cloudflare API token** and select **Save credential**.

The connection appears in the DNS Providers list. CertPing has encrypted the token into the
agent's secret store, which on the all-in-one is a set of AES-256-GCM files on the volume.

Saving does not call Cloudflare, so a wrong token is accepted here. You find out in the next
step, when the certificate fails with `DNS_AUTH_FAILED` or `DNS_ZONE_NOT_FOUND`.

## 4. Issue the first certificate

1. Open **Certificates** and select **Issue a certificate**.
2. Keep **Issuance mode** at **Automatic (connect your DNS provider)**.
3. In **Domain**, enter the name to secure, for example `app.example.com`.
4. In **Main DNS credential**, pick `cloudflare-example-com`.
5. In **Certificate authority**, pick **Let's Encrypt**. The directory we set in step 1 decides
   which Let's Encrypt answers, so this is staging.
6. Leave **Deployment targets** empty and select **Request certificate**.

The certificate appears in the list as `PENDING`. Within a few minutes it turns `ACTIVE`. Most of
that time is the agent waiting for the TXT record to show up on every nameserver of the zone.

If it turns `FAILED` instead, open it from the list. The page shows the error code and a message,
and `docker logs certping` has the agent's detail. The common codes and their fixes are in
[operations.md](operations.md#if-issuance-fails-with-a-dns-or-acme-error).

The private key was generated by the agent and stays in its secret store. The server only keeps
a reference to it.

## 5. Give CertPing a Kubernetes identity

Skip steps 5 and 6 if you have no cluster.

CertPing writes the certificate into a Kubernetes TLS secret and writes it again on every
renewal. The agent stages a new secret, promotes it to the stable name and deletes the staged
copy, so its identity needs `delete` as well as `create` and `update`. Apply this namespace,
service account, role and long-lived token, which are the same ones the end-to-end lab uses:

```sh
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata: {name: app}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: certping, namespace: app}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: certping-secrets, namespace: app}
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: certping-secrets, namespace: app}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: certping-secrets}
subjects: [{kind: ServiceAccount, name: certping, namespace: app}]
---
apiVersion: v1
kind: Secret
metadata:
  name: certping-token
  namespace: app
  annotations: {kubernetes.io/service-account.name: certping}
type: kubernetes.io/service-account-token
EOF
```

`kubectl` prints one `created` line for each of the five objects. We use a token Secret rather
than `kubectl create token` because tokens from that command expire, and deployments start
failing with `Unauthorized` when they do.

Now read the three values CertPing needs:

```sh
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'; echo   # API server URL
kubectl -n app get secret certping-token -o jsonpath='{.data.token}' | base64 -d; echo   # token
kubectl -n app get secret certping-token -o jsonpath='{.data.ca\.crt}' | base64 -d   # CA certificate
```

The first line is the API server URL, the second a long token starting with `ey`, and the rest a
PEM block that starts with `-----BEGIN CERTIFICATE-----`.

The API server URL must be reachable from inside the CertPing container. If your kubeconfig says
`https://127.0.0.1:6443`, that address points at the container itself, so use the machine's own
address or host name instead.

## 6. Deploy the certificate to Kubernetes

First register the cluster:

1. Open **Integrations**, tab **Deployment Targets**, and select **Add deployment target**.
2. Pick **Kubernetes Secrets** and enter the **Name** `my-cluster`.
3. Under **How does the agent get this secret?** choose **Paste the credential**.
4. Set **Auth method** to **Kubernetes (service account token)** and **Cluster name** to
   `my-cluster`.
5. Set **Namespace scope** to **Specific namespaces** and add `app`. CertPing writes secrets only
   in the namespaces on this list.
6. Paste the **API server URL**, the **Service account token** and the **Cluster CA certificate**
   from step 5, and select **Save credential**.

Then issue a certificate that uses it. Open **Certificates**, select **Issue a certificate** and
fill it in as in step 4, with two changes:

1. Under **Deployment targets**, pick `my-cluster`.
2. Under **Kubernetes deployment target configs**, keep **Provide explicit mapping** and enter
   the secret name `app-example-com-tls` for the `app` namespace.

Select **Request certificate**. When the certificate is `ACTIVE`, **Deployments** in the sidebar
shows a successful deployment to `my-cluster`, and the secret exists:

```console
$ kubectl -n app get secret app-example-com-tls -o jsonpath='{.data.tls\.crt}' \
    | base64 -d | openssl x509 -noout -subject -enddate
subject=CN=app.example.com
notAfter=Jan 28 10:15:00 2027 GMT
```

OpenSSL 1.1 prints `subject=CN = app.example.com`, with spaces. Your Ingress or Gateway can now
point at `app-example-com-tls`. The name stays the same across renewals.

## 7. Renew it

Every night at 03:00 UTC CertPing queues a renewal for each certificate that is due. A
certificate is due at its expiry minus the smaller of 30 days and a third of its lifetime, so this
90-day staging certificate would renew on its own 30 days before it expires. We do not want to
wait that long.

Note the current serial number:

```sh
kubectl -n app get secret app-example-com-tls -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -noout -serial
```

Open **Rotation** in the sidebar. It lists the next renewal date of each certificate. Select
**Renew now** on `app.example.com`. The certificate goes to `RENEWING`, then to `RENEW_SUCCESS`,
and **Deployments** shows a second deployment. Run the command again and it prints a different
serial: the agent issued a new certificate and replaced the secret's contents.

If you skipped Kubernetes, renew the certificate from step 4 instead and watch its state change
the same way.

## 8. Set up email

CertPing emails expiry alerts, failure notices and password-reset links to the organization's
admins. Environment variables are fixed when a container is created, so we recreate it with the
same volume and add the SMTP server. The data and the generated secrets stay on the volume.

```sh
docker rm -f certping
docker run -d --name certping \
  -p 80:80 -p 443:443 \
  -v certping:/var/lib/certping \
  -e CERTPING_URL=http://localhost \
  -e ACME_DIRECTORY_URL=https://acme-staging-v02.api.letsencrypt.org/directory \
  -e ACME_ACCOUNT_EMAIL=you@example.com \
  -e MAIL_HOST=smtp.example.com \
  -e MAIL_PORT=587 \
  -e MAIL_USERNAME=certping@example.com \
  -e MAIL_PASSWORD='your-smtp-password' \
  -e EMAIL_FROM=certping@example.com \
  ghcr.io/certping-labs/certping:0.0.1-beta
```

This start is quicker because the database exists. Our certificate is far from expiry, so no
alert is due yet. To see that mail works, sign out and, under the login form, follow
**Reset it by email**. Enter the address from step 1, and a password-reset email arrives there.
You do not have to use the link.

If nothing arrives, the notifier's error is in `docker logs certping`. An SMTP relay without TLS
or sign-in needs `MAIL_STARTTLS=false` and `MAIL_SMTP_AUTH=false`; the other mail settings are in
[configuration.md](configuration.md#email-notifier).

## 9. Move to production

Let's Encrypt production is the agent's default, so we recreate the container without
`ACME_DIRECTORY_URL` and with the host name CertPing will be served under. Point that DNS name at
the machine and open ports 80 and 443 first, because Caddy in the container gets a certificate
for CertPing itself from Let's Encrypt when the URL starts with `https://`.

```sh
docker rm -f certping
docker run -d --name certping \
  -p 80:80 -p 443:443 \
  -v certping:/var/lib/certping \
  -e CERTPING_URL=https://certping.example.com \
  -e ACME_ACCOUNT_EMAIL=you@example.com \
  -e MAIL_HOST=smtp.example.com \
  -e MAIL_PORT=587 \
  -e MAIL_USERNAME=certping@example.com \
  -e MAIL_PASSWORD='your-smtp-password' \
  -e EMAIL_FROM=certping@example.com \
  ghcr.io/certping-labs/certping:0.0.1-beta
```

The agent keeps one ACME account per organization and directory, so it registers a production
account at the next order. Select **Renew now** on the certificate, and when the renewal is done
the `issuer` line from the top of this page no longer says `(STAGING)`. Under **Integrations**,
tab **Certificate authorities**, the Let's Encrypt card now shows the agent on **Production**.

## Where next

We now have one installation with one organization, one agent, a DNS connection, a Kubernetes
target and a certificate that renews on its own. From here:

- [Concepts](architecture.md#concepts) explains why CertPing is built this way.
- [self-hosting.md](self-hosting.md) and [operations.md](operations.md) cover running it for real,
  including backups. For a server you keep, consider the [Compose kit](../deploy/compose/README.md).
- [agents.md](agents.md) shows how to run agents in other networks and clusters.
- [integrations.md](integrations.md) lists every CA, DNS provider and target.
