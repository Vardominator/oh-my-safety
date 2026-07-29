package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vardominator/oh-my-safety/internal/bridge"
	"github.com/Vardominator/oh-my-safety/internal/exposure"
	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/profile"
)

const (
	readinessSchema        = "io.oh-my-safety/agent-readiness"
	readinessSchemaVersion = 1
)

type readiness struct {
	Schema        string          `json:"schema"`
	SchemaVersion int             `json:"schema_version"`
	Ready         bool            `json:"ready"`
	StateDB       string          `json:"state_db"`
	Profile       profile.Profile `json:"profile"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	return runWithInput(arguments, os.Stdin, stdout, stderr)
}

func runWithInput(arguments []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runWithDependencies(
		arguments,
		stdin,
		stdout,
		stderr,
		defaultAgentDependencies(),
	)
}

func runWithDependencies(
	arguments []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	dependencies agentDependencies,
) error {
	dependencies = dependencies.normalized()
	defaultDB, err := defaultStateDB()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("oh-my-safety-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDB := flags.String("state-db", defaultDB, "path to the local SQLite event journal")
	preset := flags.String("profile", profile.PresetPersonal, "security profile preset")
	ingestScan := flags.String("ingest-scan", "", "ingest a schema-v1 last-scan TSV file, or - for stdin")
	history := flags.Bool("history", false, "emit journal history as versioned JSON")
	findings := flags.Bool("findings", false, "emit materialized findings as versioned JSON")
	limit := flags.Int("limit", bridge.DefaultQueryLimit, "maximum history or findings records")
	var secretRoots repeatedStringFlag
	flags.Var(&secretRoots, "scan-secrets", "scan a local file or directory for credential-like content; repeatable")
	fingerprintKey := flags.String("fingerprint-key", "", "path to the local secret-fingerprint key")
	var executablePaths repeatedStringFlag
	flags.Var(&executablePaths, "triage-executable", "triage a local executable path; repeatable")
	checkPwnedPassword := flags.Bool(
		"check-pwned-password",
		false,
		"read one password from stdin and check the HIBP k-anonymity service",
	)
	checkBreachedAccount := flags.Bool(
		"check-breached-account",
		false,
		"read one email address from stdin and check the HIBP breached-account service",
	)
	exposureContracts := flags.Bool(
		"exposure-contracts",
		false,
		"emit external exposure adapter disclosure contracts without network access",
	)
	allowNetwork := flags.Bool(
		"allow-network",
		false,
		"explicitly enable network access for an exposure check",
	)
	offline := flags.Bool(
		"offline",
		false,
		"force exposure adapters to return an offline unsupported result",
	)
	hibpAPIKeyEnv := flags.String(
		"hibp-api-key-env",
		defaultHIBPAPIKeyEnv,
		"name of the environment variable containing the HIBP API key",
	)
	managedEnroll := flags.Bool(
		"managed-enroll",
		false,
		"enroll this endpoint with an organization controller",
	)
	managedSync := flags.Bool(
		"managed-sync",
		false,
		"heartbeat, verify managed policy, and sync redacted local findings",
	)
	managedRotateCredential := flags.Bool(
		"managed-rotate-credential",
		false,
		"rotate the enrolled endpoint credential and securely replace local state",
	)
	managedPolicy := flags.Bool(
		"managed-policy",
		false,
		"emit the last verified managed policy as bounded tab-separated rows",
	)
	managedState := flags.String(
		"managed-state",
		"",
		"path to the mode-600 managed enrollment state",
	)
	controllerURL := flags.String(
		"controller-url",
		"",
		"organization controller origin used only during enrollment",
	)
	enrollmentTokenEnv := flags.String(
		"enrollment-token-env",
		defaultEnrollmentTokenEnv,
		"name of the environment variable containing the one-time enrollment token",
	)
	controllerPolicyKey := flags.String(
		"controller-policy-key",
		"",
		"pinned raw-base64 Ed25519 controller policy public key",
	)
	deviceName := flags.String(
		"device-name",
		"",
		"bounded managed device label; defaults to the local hostname",
	)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	visited := make(map[string]bool)
	flags.Visit(func(current *flag.Flag) {
		visited[current.Name] = true
	})
	ingestMode := visited["ingest-scan"]
	secretMode := visited["scan-secrets"]
	executableMode := visited["triage-executable"]
	modeCount := 0
	for _, active := range []bool{
		ingestMode,
		*history,
		*findings,
		secretMode,
		executableMode,
		*checkPwnedPassword,
		*checkBreachedAccount,
		*exposureContracts,
		*managedEnroll,
		*managedSync,
		*managedRotateCredential,
		*managedPolicy,
	} {
		if active {
			modeCount++
		}
	}
	if modeCount > 1 {
		return errors.New("agent operation modes are mutually exclusive")
	}
	if ingestMode && *ingestScan == "" {
		return errors.New("ingest-scan requires a file path or - for stdin")
	}
	if secretMode && len(secretRoots) == 0 {
		return errors.New("scan-secrets requires at least one root")
	}
	if executableMode && len(executablePaths) == 0 {
		return errors.New("triage-executable requires at least one path")
	}
	if visited["limit"] && !*history && !*findings {
		return errors.New("limit is only valid with history or findings")
	}
	if visited["fingerprint-key"] && !secretMode {
		return errors.New("fingerprint-key is only valid with scan-secrets")
	}
	if visited["fingerprint-key"] && *fingerprintKey == "" {
		return errors.New("fingerprint-key requires a file path")
	}
	exposureCheckMode := *checkPwnedPassword || *checkBreachedAccount
	if (visited["allow-network"] || visited["offline"]) && !exposureCheckMode {
		return errors.New("allow-network and offline are only valid with an exposure check")
	}
	if visited["hibp-api-key-env"] && !*checkBreachedAccount {
		return errors.New("hibp-api-key-env is only valid with check-breached-account")
	}
	managedMode := *managedEnroll ||
		*managedSync ||
		*managedRotateCredential ||
		*managedPolicy
	if visited["managed-state"] && !managedMode {
		return errors.New("managed-state is only valid with a managed operation")
	}
	for _, scoped := range []struct {
		visited bool
		name    string
	}{
		{visited["controller-url"], "controller-url"},
		{visited["enrollment-token-env"], "enrollment-token-env"},
		{visited["controller-policy-key"], "controller-policy-key"},
		{visited["device-name"], "device-name"},
	} {
		if scoped.visited && !*managedEnroll {
			return fmt.Errorf("%s is only valid with managed-enroll", scoped.name)
		}
	}
	if *managedEnroll && (*controllerURL == "" || *controllerPolicyKey == "") {
		return errors.New(
			"managed-enroll requires controller-url and controller-policy-key",
		)
	}
	if managedMode && *managedState == "" {
		*managedState, err = defaultManagedStatePath(*stateDB)
		if err != nil {
			return err
		}
	}
	if *history || *findings {
		if err := bridge.ValidateQueryLimit(*limit); err != nil {
			return err
		}
	}

	resolved, err := profile.Resolve(*preset)
	if err != nil {
		return err
	}
	var snapshot bridge.ScanSnapshot
	if ingestMode {
		snapshot, err = readScanSnapshot(*ingestScan, stdin)
		if err != nil {
			return err
		}
	}

	ctx := context.Background()
	var output any
	switch {
	case secretMode:
		keyPath := *fingerprintKey
		if keyPath == "" {
			keyPath, err = defaultFingerprintKeyPath(*stateDB)
			if err != nil {
				return err
			}
		}
		output, err = runSecretScan(
			ctx,
			secretRoots,
			keyPath,
			dependencies.Random,
		)
	case executableMode:
		output, err = runExecutableTriage(ctx, executablePaths)
	case *checkPwnedPassword:
		output, err = runPwnedPasswordCheck(
			ctx,
			stdin,
			exposure.AccessPolicy{
				Enabled: *allowNetwork,
				Offline: *offline,
			},
			dependencies.PwnedPasswordsHTTP,
		)
	case *checkBreachedAccount:
		output, err = runBreachedAccountCheck(
			ctx,
			stdin,
			exposure.AccessPolicy{
				Enabled: *allowNetwork,
				Offline: *offline,
			},
			*hibpAPIKeyEnv,
			dependencies,
		)
	case *exposureContracts:
		output, err = buildExposureContracts(dependencies)
	case *managedEnroll:
		output, err = runManagedEnrollment(
			ctx,
			*managedState,
			*controllerURL,
			*enrollmentTokenEnv,
			*controllerPolicyKey,
			*deviceName,
		)
	case *managedSync:
		output, err = runManagedSync(ctx, *managedState, *stateDB)
	case *managedRotateCredential:
		output, err = runManagedCredentialRotation(ctx, *managedState)
	case *managedPolicy:
		output, err = runManagedPolicy(*managedState)
	default:
		store, openErr := journal.Open(*stateDB)
		if openErr != nil {
			return openErr
		}
		switch {
		case ingestMode:
			output, err = bridge.IngestScan(ctx, store, snapshot)
		case *history:
			output, err = bridge.History(ctx, store, *limit)
		case *findings:
			output, err = bridge.Findings(ctx, store, *limit)
		default:
			output = readiness{
				Schema:        readinessSchema,
				SchemaVersion: readinessSchemaVersion,
				Ready:         true,
				StateDB:       *stateDB,
				Profile:       resolved,
			}
		}
		if err != nil {
			_ = store.Close()
			return err
		}
		if err := store.Close(); err != nil {
			return fmt.Errorf("close local journal: %w", err)
		}
	}
	if err != nil {
		return err
	}
	if flatPolicy, ok := output.(managedPolicyOutput); ok {
		return flatPolicy.writeTo(stdout)
	}

	return json.NewEncoder(stdout).Encode(output)
}

func defaultStateDB() (string, error) {
	if stateRoot := os.Getenv("XDG_STATE_HOME"); stateRoot != "" {
		return filepath.Join(stateRoot, "oh-my-safety", "journal.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user state directory: %w", err)
	}
	if home == "" {
		return "", errors.New("user home directory is empty")
	}
	return filepath.Join(home, ".local", "state", "oh-my-safety", "journal.db"), nil
}

func readScanSnapshot(fileName string, stdin io.Reader) (bridge.ScanSnapshot, error) {
	if fileName == "-" {
		return bridge.ParseScan(stdin)
	}
	if fileName == "" || strings.ContainsRune(fileName, '\x00') {
		return bridge.ScanSnapshot{}, errors.New("scan file path is invalid")
	}
	clean := filepath.Clean(fileName)
	if !filepath.IsAbs(fileName) &&
		(clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))) {
		return bridge.ScanSnapshot{}, errors.New("relative scan path must not traverse outside the current directory")
	}
	info, err := os.Lstat(fileName)
	if err != nil {
		return bridge.ScanSnapshot{}, errors.New("open scan file")
	}
	if !info.Mode().IsRegular() {
		return bridge.ScanSnapshot{}, errors.New("scan input must be a regular file")
	}
	file, err := os.Open(fileName)
	if err != nil {
		return bridge.ScanSnapshot{}, errors.New("open scan file")
	}
	snapshot, parseErr := bridge.ParseScan(file)
	closeErr := file.Close()
	if parseErr != nil {
		return bridge.ScanSnapshot{}, parseErr
	}
	if closeErr != nil {
		return bridge.ScanSnapshot{}, errors.New("close scan file")
	}
	return snapshot, nil
}
