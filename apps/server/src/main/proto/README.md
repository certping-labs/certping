# Internal gRPC contracts

Java stubs are generated from these files on every build
(`protobuf-maven-plugin` in `pom.xml`) into `target/`; nothing generated is
committed.

| File | Served by | Copied by |
| --- | --- | --- |
| `certping/internal/v1/notification_policy.proto` | the server (`internal/grpc/NotificationPolicyGrpcService`) | the notifier, unedited |

The contract is owned here. Change it here first, compatibly (new fields and
calls only), then copy it to `apps/notifier/src/main/proto`. See
[docs/architecture.md](../../../../../docs/architecture.md#internal-grpc).
