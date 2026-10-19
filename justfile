set positional-arguments

coverage_floor := "89"

# Print coverage per function. View cover.out with `go tool cover -html=cover.out`.
cover:
    go test -coverprofile=cover.out ./...
    go tool cover -func=cover.out

# Fail if total coverage is below the floor.
cover-check floor=coverage_floor: cover
    #!/usr/bin/env bash
    set -euo pipefail
    floor=$1
    total=$(go tool cover -func=cover.out | awk '/^total:/ { sub("%", "", $NF); print $NF }')
    if awk -v t="$total" -v f="$floor" 'BEGIN { exit !(t < f) }'; then
        echo "coverage $total% is below the $floor% floor"
        exit 1
    fi
    echo "coverage $total% meets the $floor% floor"

# Run mutation testing. A LIVED mutant is a code change no test catches.
mutate *args:
    go run github.com/go-gremlins/gremlins/cmd/gremlins@v0.6.0 unleash --timeout-coefficient 10 "$@"
