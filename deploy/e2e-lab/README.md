# End-to-end lab

Runs every CertPing flow for real on one machine, with nothing public involved. `run.sh` runs 14
checks in this order and prints PASS or FAIL for each:

| # | Check | What is real |
| --- | --- | --- |
| 1 | Sign in | The first admin's generated password, then the forced password change |
| 2 | DNS credential | A credential for the CertPing DNS API stand-in is accepted |
| 3 | Kubernetes credential | A service account token for k3s is accepted |
| 4 | Issue and deploy | An ACME DNS-01 order against Pebble (Let's Encrypt's test CA). The agent writes the TXT record, the propagation check queries the authoritative server, Pebble validates over DNS, and the certificate is written as a TLS secret into k3s |
| 5 | Certificate authorities | `GET /api/v1/certificate-authorities` shows the agent's ACME account (Pebble, custom CA) and no key material |
| 6 | Agents page | `GET /api/v1/agents` shows the bundled agent online with its version, store and capabilities, and no token or secret |
| 7 | Discover | A Kubernetes scan finds that secret and marks it managed by CertPing |
| 8 | Renew | A renewal on request issues a new certificate and replaces the secret |
| 9 | Email | Notifications arrive in a Mailpit mailbox |
| 10 | Expiry alert | An expiry alert email for a certificate inside the 14-day window |
| 11 | Scheduled renewal | The scheduler renews a due certificate on its own and redeploys it |
| 12 | Admin recovery | `certping-admin reset-password` gives a working reset link, no email needed |
| 13 | Reset links hidden | Reset links never appear in the notification list or the stored records |
| 14 | Value summary | The counts of issuances, renewals and deployments match the work done |

Needs Docker, Python 3 and OpenSSL. About 4 GB of memory. Ports 8090 (CertPing) and 8025
(Mailpit) must be free.

The lab runs the image `certping-allinone:dev` (or the one named in `CERTPING_IMAGE`). Build it
first, from the repository root:

```sh
make images
```

Then, in this folder:

```sh
./run.sh          # fresh lab, run every check
./run.sh --keep   # run again on the same lab
./run.sh --down   # stop and remove everything
```

Then open http://localhost:8090 (password in `.work/admin-password`) and http://localhost:8025 for the mail.

## What is in it

- `coredns`: authoritative DNS for `lab.test`; the CertPing container uses it as its resolver.
- `dnsapi`: a small stand-in for the CertPing DNS API that writes records into the zone CoreDNS serves.
- `pebble`: the ACME CA. Its certificates last ten days, so expiry alerts and renewal timing can be exercised.
- `k3s`: a one-node Kubernetes cluster for deployment and discovery.
- `mailpit`: catches outgoing email.
- `certping`: the all-in-one image, set up with `ACME_DIRECTORY_URL`, `CERTPING_EXTRA_CA_CERTS` (to trust Pebble) and the mailbox.

Cloud targets (AWS, Azure, GCP) are not in the lab; they need real accounts.

## Load test

`load.py` loads the running lab (start it with `./run.sh` first) and measures how CertPing holds up.
It signs in once with `.work/admin-password` and keeps the token in `.work/load-token.json`, because
sign-in is limited to 20 attempts per 5 minutes.

```sh
python3 load.py issue -n 1000     # issue 1000 certificates (names <prefix>NNNN.lab.test), each deployed to k3s
python3 load.py renew             # make all of them due at once; the renewal job (every minute here) renews them
python3 load.py idle -k 200       # 60 s baseline, then 200 simulated idle agents for 5 minutes (--duration)
python3 load.py combined -k 200   # 200 idle agents plus a renewal storm of the issued certificates
python3 load.py all               # the four phases in that order
```

- The issue phase submits with `--submit-concurrency` (16) parallel requests and waits until every
  certificate is active and deployed, or nothing has changed for `--stall` seconds (600).
- The renew and combined phases renew the certificates of the last issue phase (`.work/load-state.json`).
- Idle agents get their own agent tokens in their own organizations (`--idle-orgs`, default 1), so they
  never take real work from the bundled agent. Each one long-polls `GET /api/v1/agent-gateway/messages`
  exactly as the agent's `GatewayClient` does (`queue=inbound&max=1&waitSeconds=20`). Tokens are kept in
  `.work/load-state.json` and reused on the next run.
- Every phase samples every 5 seconds: `docker stats` of the CertPing container, CPU per process inside it
  (server, agent, notifier, PostgreSQL), PostgreSQL transactions per second, connections per owner and
  state, connections busy in a statement (40 snapshots a second), and `message_queue` depth per channel.
- Results: a summary on screen and the full data in `.work/load-<phase>-<time>.json`. To end a long
  phase early and still get its report, `touch .work/load-stop`.

The all-in-one image runs PostgreSQL, Valkey, the server, the agent and the notifier in one container
(4 GB here), so the numbers are for one box sharing the CPUs and memory Docker gives it.
