# Steel Beach Hive push gateway

This deployment uses a Buzz relay and Apple's APNs for the locally signed `net.steelbeach.hive` app. Set the registration endpoint to your relay's public base URL; the relay delivers internally to `http://push-gateway:8080/v1/deliveries/apns`.

The existing Tailscale Funnel publishes the proxy on port 443. App Attest limits registration to the configured signed app. Relay invitations and read permissions control which events may match a lease. Funnel itself is public; it does not impose the relay's invitation rules on gateway registration.

## Start and check

Credentials are stored outside Git in `~/.config/steelbeach/hive-push` (directory mode 0700, credential files 0600). The sandbox APNs provider key is read-only mounted and restricted in Apple Developer to the sandbox. The production provider key is separately mounted and restricted to production and Hive's `net.steelbeach.hive` topic. Never copy these files into the repository or build context.

```sh
export HIVE_PUSH_SECRETS_DIR="$HOME/.config/steelbeach/hive-push"
export HIVE_PUSH_RELAY_NETWORK="your-relay-project_buzz-net"
docker build -f deploy/compose/hive-push/Dockerfile -t steelbeach/buzz-push-gateway:hive .
docker compose -f deploy/compose/hive-push/compose.yml up -d
curl --fail http://127.0.0.1:3003/_readiness
```

The compose deployment runs migrations as a separate administrator, then starts the gateway with a database role that cannot alter the schema. PostgreSQL remains on an internal Docker network. Its persistent volume and independent encryption keys must be backed up together; replacing the keys makes existing encrypted endpoints or grants unusable.

The relay's `compose.hive-push.yml` overlay pins the upgraded official relay image and enables NIP-PL. The existing nginx configuration adds `/v1/` routing to `push-gateway:8080`. Reload nginx after recreating a relay or gateway container because its upstream address may change.

## App behavior

Hive's opt-in covers mentions and direct messages for the active community. The relay only receives an encrypted notification lease. Apple receives the fixed generic “New message” alert, without message contents. The iOS notification extension uses the active identity to fetch recent signed messages directly from the private relay and display the sender and a preview. It shares the existing device-only identity through the app’s Keychain access group. If fetching fails or times out, “New message” remains. Tapping a direct-message preview opens that conversation. Opening Hive renews registration when needed; authority expires after 30 days without renewal. A development-signed app must be refreshed when its provisioning profile expires.

The Xcode local config sets `HIVE_PUSH_GATEWAY_URL` to the relay's `/v1/deliveries/apns` endpoint (escape `//` as `/$()/` in `.xcconfig` files). Keep environment-specific hostnames in local, untracked configuration. The gateway accepts the `buzz-ios-sandbox` profile for local builds and routes those tokens to APNs sandbox with the sandbox provider key; TestFlight's `buzz-ios-production` profile routes to APNs production with its separate production provider key. Both use the same production App Attest identity.

## Placeholder and foreground behavior

The private relay uses `steelbeach/buzz-relay:hive-placeholder-filter`, built with `Dockerfile.relay`. It retains the pinned official runtime and web assets and replaces only the relay binary. Rebuild it after relay source changes:

```sh
docker build -f deploy/compose/hive-push/Dockerfile.relay -t steelbeach/buzz-relay:hive-placeholder-filter .
```

Push matching skips blank kind-9/40002 messages and standalone `.` kind-9 placeholders. Attachment-tagged messages remain eligible, as do subsequent real replies. Message history is preserved. The phone uses the same placeholder rule when choosing a preview, and suppresses remote system banners while Hive is in the foreground; local reminders retain their alerts.

## Verification and rollback

Native gateway tests include provider JWT caching and payload checks. Database integration tests can use `compose.tests.yml`, which temporarily publishes PostgreSQL only on localhost. Remove the overlay afterward. A live ignored test `live_provider_key_authenticates_with_sandbox` checks Apple accepts the provider credentials using an intentionally invalid endpoint; it sends no notification to a device.

Before a relay upgrade, save private database and proxy backups in an operator-controlled location. A database restore may be required to roll back schema migrations; do not downgrade a migrated database blindly. Disable push routing and stop the gateway before a restore. Preserve the gateway database volume and secret directory when stopping this deployment.
