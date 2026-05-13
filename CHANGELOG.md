# Changelog

All notable changes to therelic (the open-source runtime) are
documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/) once it
cuts its first tag.

Cross-repo contracts referenced below live in
[RELIC.md](https://github.com/therelicai/therelic-platform/blob/main/RELIC.md).

## [Unreleased]

### Added — Slice 15: Universal policy hot-reload

- **`api.Client.SubscribePolicyUpdates`** — opens an authenticated SSE
  connection against `GET /v1/agents/:name/policy_updates` and yields
  one `PolicyUpdate` per `event: policy_update` frame. Hand-rolled
  SSE reader (same rationale as slice 14: fetch is the source of
  truth, no external dependency on an SSE library).
- **`api.Client.ReportPolicyApplied`** — POSTs `{hash}` to
  `/v1/agents/:name/policy_applied`. Called after a successful
  `eng.SwapPolicy` to advance the dashboard's apply counter.
- **`--watch` swap** in `internal/cli/run.go`: removed the fsnotify
  watcher; replaced with `runPolicyWatcher` goroutine that subscribes
  to the platform's policy-updates SSE channel, pulls policy on each
  notification, `SwapPolicy`'s the engine, and reports applied. Single
  reload mechanism — no parallel paths. `--watch` without API
  credentials is now a no-op with a clear stderr message.

### Invariants preserved across hot-reload

- **In-flight `Evaluate` calls complete under their starting policy.**
  `Engine.Evaluate` reads the policy pointer under RLock; `SwapPolicy`
  publishes a new pointer atomically. Pinned by
  `internal/policy/engine_swap_concurrent_test.go` under the race
  detector (16 workers, 200 swaps; zero "weird" decisions).
- **The per-run HMAC trace chain key is not rotated.** `SwapPolicy`
  only touches the policy pointer; the chain key bound to the writer
  at run start stays in place. A run that started under v1 verifies
  end-to-end after any number of swaps to v2/v3/….

### Breaking change

- `relic run --watch` previously used fsnotify on the local policy
  file. It now requires `RELIC_API_KEY` + `RELIC_API_URL` and
  subscribes to the control plane's SSE channel instead. Standalone
  runs without `--watch` are unchanged.

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
