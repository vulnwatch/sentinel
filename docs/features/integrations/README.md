# Integrations

Technical boundaries for authoritative IBS REST evidence and RabbitMQ wake-up
delivery.

## Specs

```
ibs-integration.md            IBS REST source/request evidence and anonymous Product repository downloads
ibs-rabbitmq-integration.md   Standalone IBS RabbitMQ wake-up consumer, heartbeat, status API
```

## Relationships

- `ibs-integration.md` defines the credentialed IBS API client used by track
  release detection and submission tracking, plus the separate anonymous
  Product repository download boundary used by Product release detection.
  Package maintainership is consumed from SMELT, not IBS.
- `ibs-rabbitmq-integration.md` defines the standalone event consumer that uses
  package and request events only to accelerate the polling-owned track release
  and submission reconciliation workflows. It also owns the ephemeral
  heartbeat and consumer-status API.
- Both specs are pure infrastructure — business logic lives in
  `packages/` and `tickets/` specs that consume these layers.
