// Command oh-my-safety-intel manages signed, offline intelligence bundles.
// It reads and writes local files only; it never fetches or executes content.
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type application struct {
	stdout io.Writer
	now    func() time.Time
	random io.Reader
}

type errorResponse struct {
	Error string `json:"error"`
}

type helpResponse struct {
	Commands []string `json:"commands"`
}

var errUsage = errors.New("intel-cli: invalid command or arguments")

func main() {
	app := application{
		stdout: os.Stdout,
		now:    time.Now,
		random: rand.Reader,
	}
	if err := app.run(os.Args[1:]); err != nil {
		_ = writeJSON(os.Stderr, errorResponse{Error: err.Error()})
		os.Exit(1)
	}
}

func (app application) run(arguments []string) error {
	if app.stdout == nil || app.now == nil || app.random == nil {
		return errors.New("intel-cli: invalid application configuration")
	}
	if len(arguments) == 0 {
		return errUsage
	}
	switch arguments[0] {
	case "help", "-h", "--help":
		return writeJSON(app.stdout, helpResponse{Commands: []string{
			"keygen --key-id ID --private-key FILE --trust-store FILE",
			"sign --input FILE --private-key FILE --output FILE",
			"verify --bundle FILE --trust-store FILE [--agent-schema N] [--at RFC3339] [--clock-skew DURATION]",
			"install --bundle FILE --trust-store FILE --dir DIRECTORY [--agent-schema N] [--at RFC3339] [--clock-skew DURATION]",
			"current --dir DIRECTORY --trust-store FILE [--agent-schema N] [--at RFC3339] [--clock-skew DURATION]",
		}})
	case "keygen":
		return app.keygen(arguments[1:])
	case "sign":
		return app.sign(arguments[1:])
	case "verify":
		return app.verify(arguments[1:])
	case "install":
		return app.install(arguments[1:])
	case "current":
		return app.current(arguments[1:])
	default:
		return errUsage
	}
}

func writeJSON(destination io.Writer, value any) error {
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("intel-cli: write JSON output: %w", err)
	}
	return nil
}
