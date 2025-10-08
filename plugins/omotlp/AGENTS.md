# AGENTS.md – omotlp output module

These instructions apply to files inside `plugins/omotlp/`.

## Development notes
- Keep the module pure C unless the optional gRPC shim is enabled.
- Update `MODULE_METADATA.yaml` and the user documentation when adding new
  configuration parameters or behavioral changes.
- Refresh the concurrency note in `omotlp.c` if locking expectations change.
- Run `devtools/format-code.sh` before committing.

## Testing
- Stand up targeted shell tests under `tests/` named `omotlp-*.sh`.
- For now there is no dedicated test harness; add one before enabling
  transports.
