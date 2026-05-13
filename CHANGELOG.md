# Changelog

All notable changes to therelic (the open-source runtime) are
documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/) once it
cuts its first tag.

Cross-repo contracts referenced below live in
[RELIC.md](https://github.com/therelicai/therelic-platform/blob/main/RELIC.md).

## [Unreleased]

### Added — Slice 14b: Streaming intents

- **`IntentEvent` trace type** (additive). Emitted by the MCP proxy
  immediately after intent parsing and before `policy.Engine.Evaluate`
  produces a verdict. The matching `ActionEvent` is still emitted
  after the verdict as before; the two share the same `seq` so
  subscribers can pair them. Sealed into the HMAC chain when
  `RELIC_TRACE_KEY` is set.
- **`TraceWriter.WriteIntent`** + **`TraceWriter.SetSealedSink`** — the
  sink hook tees every sealed line into a caller-provided callback so
  the streaming flush sees byte-identical bytes to what lands on disk.
- **`MCPProxy.SetIntentEmitter`** — registers the intent callback. The
  proxy is otherwise unchanged; constructor signature preserved.
- **`internal/api/stream.go`** — optional streaming flush. When
  `RELIC_API_URL` + `RELIC_API_KEY` are both set the runtime POSTs
  each sealed event to `/v1/intents`. Bounded queue (256 events),
  drop-on-overflow, 2-second per-request timeout. Never blocks the
  proxy's hot path.

### Constraints respected (slice 14b)

- `ActionEvent`, `RunEvent`, `PolicyReloadEvent` are unchanged.
  Existing `.trtrace` consumers (older platforms, `relic trace
  verify`) work without modification.
- **Standalone mode is preserved.** With no `RELIC_API_KEY` set, the
  streamer returns `nil` and no network traffic is generated. The
  batch trace push at end-of-run remains the durable path.
- Per-run HMAC chain key is unchanged; sealed `IntentEvent` lines
  extend the same chain.
- The proxy's constraint counter (`actionCount`) increments *after*
  `Evaluate` returns, preserving slice-13 `max_actions` semantics.

### Tests added

- `internal/proxy/intent_order_test.go` — pins "IntentEvent strictly
  precedes ActionEvent for the same seq."
- `internal/api/stream_test.go` — standalone mode, delivery, overflow.
