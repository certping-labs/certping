# Internal gRPC contracts

Copies of contracts the server owns. Java stubs are generated from them on
every build (`protobuf-maven-plugin` in `pom.xml`) into `target/`; nothing
generated is committed.

| File | Owned by | Used for |
| --- | --- | --- |
| `certping/internal/v1/notification_policy.proto` | `apps/server/src/main/proto` | asking the server whether an organization turned a notification off (`CertManagerNotificationPolicy`) |

To pick up a change, copy the file over from the server unedited.
