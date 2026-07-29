package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/intel"
)

type unsignedBundle struct {
	Schema             string         `json:"schema,omitempty"`
	SchemaVersion      int            `json:"schema_version,omitempty"`
	BundleID           string         `json:"bundle_id"`
	Sequence           uint64         `json:"sequence"`
	IssuedAt           time.Time      `json:"issued_at"`
	ExpiresAt          time.Time      `json:"expires_at"`
	MinimumAgentSchema int            `json:"minimum_agent_schema"`
	Records            []intel.Record `json:"records"`
}

type verificationFlags struct {
	agentSchema int
	at          string
	clockSkew   time.Duration
}

type keygenOutput struct {
	Command        string `json:"command"`
	KeyID          string `json:"key_id"`
	PrivateKeyFile string `json:"private_key_file"`
	TrustStoreFile string `json:"trust_store_file"`
}

type bundleSummary struct {
	BundleID           string    `json:"bundle_id"`
	Sequence           uint64    `json:"sequence"`
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	MinimumAgentSchema int       `json:"minimum_agent_schema"`
	PayloadSHA256      string    `json:"payload_sha256"`
	KeyID              string    `json:"key_id"`
	RecordCount        int       `json:"record_count"`
}

type signOutput struct {
	Command string        `json:"command"`
	Output  string        `json:"output"`
	Bundle  bundleSummary `json:"bundle"`
}

type verifyOutput struct {
	Command string        `json:"command"`
	Valid   bool          `json:"valid"`
	Bundle  bundleSummary `json:"bundle"`
}

type installOutput struct {
	Command   string                `json:"command"`
	Installed bool                  `json:"installed"`
	Replay    bool                  `json:"replay"`
	Metadata  intel.CurrentMetadata `json:"metadata"`
}

type currentOutput struct {
	Command  string                `json:"command"`
	Metadata intel.CurrentMetadata `json:"metadata"`
	Bundle   bundleSummary         `json:"bundle"`
	Records  []intel.Record        `json:"records"`
}

func (app application) keygen(arguments []string) error {
	flags := newFlagSet("keygen")
	var keyID, privatePath, trustPath string
	flags.StringVar(&keyID, "key-id", "", "")
	flags.StringVar(&privatePath, "private-key", "", "")
	flags.StringVar(&trustPath, "trust-store", "", "")
	if err := parseFlags(flags, arguments); err != nil ||
		!keyIDPattern.MatchString(keyID) ||
		privatePath == "" ||
		trustPath == "" {
		return errUsage
	}
	privateAbsolute, err := filepath.Abs(privatePath)
	if err != nil {
		return errUsage
	}
	trustAbsolute, err := filepath.Abs(trustPath)
	if err != nil || privateAbsolute == trustAbsolute {
		return errUsage
	}
	if err := pathAvailable(privatePath); err != nil {
		return err
	}
	if err := pathAvailable(trustPath); err != nil {
		return err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(app.random)
	if err != nil {
		return errors.New("intel-cli: cannot generate Ed25519 key")
	}
	defer clear(privateKey)
	privateJSON, err := json.Marshal(privateKeyDocument{
		Schema:        privateKeySchema,
		SchemaVersion: privateKeySchemaVersion,
		KeyID:         keyID,
		PrivateKey:    privateKey,
	})
	if err != nil {
		return errInvalidPrivateKey
	}
	defer clear(privateJSON)
	trustJSON, err := trustDocument(keyID, publicKey)
	if err != nil {
		return errors.New("intel-cli: cannot encode trust store")
	}

	if err := writeExclusive(privatePath, privateJSON); err != nil {
		return err
	}
	privateCreated := true
	defer func() {
		if privateCreated {
			_ = os.Remove(privatePath)
		}
	}()
	if err := writeExclusive(trustPath, trustJSON); err != nil {
		return err
	}
	privateCreated = false

	return writeJSON(app.stdout, keygenOutput{
		Command:        "keygen",
		KeyID:          keyID,
		PrivateKeyFile: privatePath,
		TrustStoreFile: trustPath,
	})
}

func (app application) sign(arguments []string) error {
	flags := newFlagSet("sign")
	var inputPath, privatePath, outputPath string
	flags.StringVar(&inputPath, "input", "", "")
	flags.StringVar(&privatePath, "private-key", "", "")
	flags.StringVar(&outputPath, "output", "", "")
	if err := parseFlags(flags, arguments); err != nil ||
		inputPath == "" ||
		privatePath == "" ||
		outputPath == "" {
		return errUsage
	}

	limits := intel.DefaultLimits()
	encoded, err := readLocalFile(inputPath, limits.MaxBundleBytes, false)
	if err != nil {
		return err
	}
	var unsigned unsignedBundle
	if err := decodeStrict(encoded, &unsigned); err != nil {
		return err
	}
	keyID, privateKey, err := loadPrivateKey(privatePath)
	if err != nil {
		return err
	}
	defer clear(privateKey)
	bundle := intel.Bundle{
		Schema:             unsigned.Schema,
		SchemaVersion:      unsigned.SchemaVersion,
		BundleID:           unsigned.BundleID,
		Sequence:           unsigned.Sequence,
		IssuedAt:           unsigned.IssuedAt,
		ExpiresAt:          unsigned.ExpiresAt,
		MinimumAgentSchema: unsigned.MinimumAgentSchema,
		Records:            unsigned.Records,
	}
	signed, canonical, err := intel.Sign(bundle, keyID, privateKey, limits)
	if err != nil {
		return err
	}
	if err := writeExclusive(outputPath, canonical); err != nil {
		return err
	}
	return writeJSON(app.stdout, signOutput{
		Command: "sign",
		Output:  outputPath,
		Bundle:  summarize(signed),
	})
}

func (app application) verify(arguments []string) error {
	flags := newFlagSet("verify")
	var bundlePath, trustPath string
	flags.StringVar(&bundlePath, "bundle", "", "")
	flags.StringVar(&trustPath, "trust-store", "", "")
	verification := addVerificationFlags(flags)
	if err := parseFlags(flags, arguments); err != nil ||
		bundlePath == "" ||
		trustPath == "" {
		return errUsage
	}
	options, err := verification.options(app.now)
	if err != nil {
		return err
	}
	encoded, err := readLocalFile(bundlePath, intel.DefaultLimits().MaxBundleBytes, false)
	if err != nil {
		return err
	}
	trustStore, err := intel.LoadTrustStore(trustPath)
	if err != nil {
		return err
	}
	verified, err := intel.Verify(encoded, trustStore, options)
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, verifyOutput{
		Command: "verify",
		Valid:   true,
		Bundle:  summarize(verified.Bundle),
	})
}

func (app application) install(arguments []string) error {
	flags := newFlagSet("install")
	var bundlePath, trustPath, directory string
	flags.StringVar(&bundlePath, "bundle", "", "")
	flags.StringVar(&trustPath, "trust-store", "", "")
	flags.StringVar(&directory, "dir", "", "")
	verification := addVerificationFlags(flags)
	if err := parseFlags(flags, arguments); err != nil ||
		bundlePath == "" ||
		trustPath == "" ||
		directory == "" {
		return errUsage
	}
	options, err := verification.options(app.now)
	if err != nil {
		return err
	}
	encoded, err := readLocalFile(bundlePath, intel.DefaultLimits().MaxBundleBytes, false)
	if err != nil {
		return err
	}
	trustStore, err := intel.LoadTrustStore(trustPath)
	if err != nil {
		return err
	}
	result, err := intel.Install(
		context.Background(),
		encoded,
		trustStore,
		directory,
		intel.InstallOptions{Verify: options},
	)
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, installOutput{
		Command:   "install",
		Installed: result.Installed,
		Replay:    result.Replay,
		Metadata:  result.Metadata,
	})
}

func (app application) current(arguments []string) error {
	flags := newFlagSet("current")
	var directory, trustPath string
	flags.StringVar(&directory, "dir", "", "")
	flags.StringVar(&trustPath, "trust-store", "", "")
	verification := addVerificationFlags(flags)
	if err := parseFlags(flags, arguments); err != nil ||
		directory == "" ||
		trustPath == "" {
		return errUsage
	}
	options, err := verification.options(app.now)
	if err != nil {
		return err
	}
	trustStore, err := intel.LoadTrustStore(trustPath)
	if err != nil {
		return err
	}
	metadata, encoded, err := intel.ReadCurrent(directory, options.Limits)
	if err != nil {
		return err
	}
	verified, err := intel.Verify(encoded, trustStore, options)
	if err != nil {
		return err
	}
	return writeJSON(app.stdout, currentOutput{
		Command:  "current",
		Metadata: metadata,
		Bundle:   summarize(verified.Bundle),
		Records:  verified.Bundle.Records,
	})
}

func newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(ioDiscard{})
	return flags
}

type ioDiscard struct{}

func (ioDiscard) Write(content []byte) (int, error) {
	return len(content), nil
}

func parseFlags(flags *flag.FlagSet, arguments []string) error {
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errUsage
	}
	return nil
}

func addVerificationFlags(flags *flag.FlagSet) *verificationFlags {
	values := &verificationFlags{}
	flags.IntVar(&values.agentSchema, "agent-schema", 1, "")
	flags.StringVar(&values.at, "at", "", "")
	flags.DurationVar(&values.clockSkew, "clock-skew", 0, "")
	return values
}

func (values verificationFlags) options(now func() time.Time) (intel.VerifyOptions, error) {
	if values.agentSchema <= 0 || values.clockSkew < 0 {
		return intel.VerifyOptions{}, errUsage
	}
	verificationTime := now().UTC()
	if values.at != "" {
		parsed, err := time.Parse(time.RFC3339Nano, values.at)
		if err != nil {
			return intel.VerifyOptions{}, errors.New("intel-cli: invalid verification time")
		}
		verificationTime = parsed.UTC()
	}
	return intel.VerifyOptions{
		Limits:      intel.DefaultLimits(),
		Now:         verificationTime,
		ClockSkew:   values.clockSkew,
		AgentSchema: values.agentSchema,
	}, nil
}

func summarize(bundle intel.Bundle) bundleSummary {
	return bundleSummary{
		BundleID:           bundle.BundleID,
		Sequence:           bundle.Sequence,
		IssuedAt:           bundle.IssuedAt,
		ExpiresAt:          bundle.ExpiresAt,
		MinimumAgentSchema: bundle.MinimumAgentSchema,
		PayloadSHA256:      bundle.PayloadSHA256,
		KeyID:              bundle.KeyID,
		RecordCount:        len(bundle.Records),
	}
}
