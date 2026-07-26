---
description: Implement the next spec phase and stop at its acceptance criteria
---

Implement phase $ARGUMENTS of `vrm-spec.md`. If no phase number was given, work out the
next unimplemented phase from the repo state and say which one you picked before starting.

Steps:

1. Re-read that phase's section in the spec, plus any sections it references.
2. State the acceptance criteria back before writing code.
3. Implement only that phase. Do not start the next one. Do not add scope the phase
   doesn't call for.
4. Run: `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test -race ./...`
5. Go through each acceptance criterion one at a time and say what specifically satisfies
   it. If one isn't met, say so plainly rather than rounding up.
6. Stop for review.

If the phase can't be completed as specified — a missing endpoint, an ambiguity, an
external API that doesn't behave as the spec assumes — stop and ask instead of improvising.
