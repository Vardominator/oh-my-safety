package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Vardominator/oh-my-safety/internal/exposure"
	"github.com/Vardominator/oh-my-safety/internal/scanner"
)

const (
	defaultFingerprintKeyName = "fingerprint.key"
	fingerprintKeyBytes       = 32
	maxPasswordInputBytes     = 1024
	maxEmailInputBytes        = 254
	defaultHIBPAPIKeyEnv      = "HIBP_API_KEY"

	pwnedPasswordCheckSchema        = "io.oh-my-safety/pwned-password-check"
	breachedAccountCheckSchema      = "io.oh-my-safety/breached-account-check"
	exposureContractsSchema         = "io.oh-my-safety/exposure-contracts"
	securityModeSchemaVersion       = 1
	disabledBreachedAccountAPIKey   = "00000000000000000000000000000000"
	maxEnvironmentVariableNameBytes = 128
)

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *repeatedStringFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type agentDependencies struct {
	Random              io.Reader
	LookupEnv           func(string) (string, bool)
	PwnedPasswordsHTTP  exposure.HTTPOptions
	BreachedAccountHTTP exposure.HTTPOptions
}

func defaultAgentDependencies() agentDependencies {
	return agentDependencies{
		Random:    rand.Reader,
		LookupEnv: os.LookupEnv,
	}
}

func (dependencies agentDependencies) normalized() agentDependencies {
	if dependencies.Random == nil {
		dependencies.Random = rand.Reader
	}
	if dependencies.LookupEnv == nil {
		dependencies.LookupEnv = os.LookupEnv
	}
	return dependencies
}

type pwnedPasswordCheckEnvelope struct {
	Schema        string                   `json:"schema"`
	SchemaVersion int                      `json:"schema_version"`
	Contract      exposure.AdapterContract `json:"contract"`
	Result        exposure.PasswordResult  `json:"result"`
}

type breachedAccountCheckEnvelope struct {
	Schema        string                         `json:"schema"`
	SchemaVersion int                            `json:"schema_version"`
	Contract      exposure.AdapterContract       `json:"contract"`
	Result        exposure.BreachedAccountResult `json:"result"`
}

type exposureContractsEnvelope struct {
	Schema        string                     `json:"schema"`
	SchemaVersion int                        `json:"schema_version"`
	Contracts     []exposure.AdapterContract `json:"contracts"`
}

func defaultFingerprintKeyPath(stateDB string) (string, error) {
	if err := validateFileArgument(stateDB, "state database path"); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(stateDB), defaultFingerprintKeyName), nil
}

func runSecretScan(
	ctx context.Context,
	roots []string,
	keyPath string,
	random io.Reader,
) (scanner.SecretResult, error) {
	normalizedRoots, err := validateSecretRoots(roots)
	if err != nil {
		return scanner.SecretResult{}, err
	}
	if err := validateFileArgument(keyPath, "fingerprint key path"); err != nil {
		return scanner.SecretResult{}, err
	}
	key, err := loadOrCreateFingerprintKey(keyPath, random)
	if err != nil {
		return scanner.SecretResult{}, err
	}
	defer zeroBytes(key)

	secretScanner, err := scanner.NewSecretScanner(scanner.SecretOptions{
		FingerprintKey: key,
	})
	if err != nil {
		return scanner.SecretResult{}, errors.New("initialize local secret scanner")
	}
	result, err := secretScanner.Scan(ctx, normalizedRoots...)
	if err != nil {
		return result, errors.New("local secret scan failed")
	}
	return result, nil
}

func runExecutableTriage(
	ctx context.Context,
	paths []string,
) (scanner.ExecutableResult, error) {
	candidates, err := executableCandidates(paths)
	if err != nil {
		return scanner.ExecutableResult{}, err
	}
	executableScanner, err := scanner.NewExecutableScanner(scanner.ExecutableOptions{})
	if err != nil {
		return scanner.ExecutableResult{}, errors.New("initialize executable scanner")
	}
	result, err := executableScanner.Triage(ctx, candidates)
	if err != nil {
		return result, errors.New("local executable triage failed")
	}
	return result, nil
}

func runPwnedPasswordCheck(
	ctx context.Context,
	stdin io.Reader,
	policy exposure.AccessPolicy,
	httpOptions exposure.HTTPOptions,
) (pwnedPasswordCheckEnvelope, error) {
	client, err := exposure.NewPwnedPasswordsClient(exposure.PwnedPasswordsConfig{
		Policy: policy,
		HTTP:   httpOptions,
	})
	if err != nil {
		return pwnedPasswordCheckEnvelope{}, err
	}
	password, err := readOneSensitiveInput(stdin, maxPasswordInputBytes, "password")
	if err != nil {
		return pwnedPasswordCheckEnvelope{}, err
	}
	defer zeroBytes(password)

	result, err := client.Check(ctx, string(password))
	if err != nil {
		return pwnedPasswordCheckEnvelope{}, err
	}
	return pwnedPasswordCheckEnvelope{
		Schema:        pwnedPasswordCheckSchema,
		SchemaVersion: securityModeSchemaVersion,
		Contract:      client.Contract(),
		Result:        result,
	}, nil
}

func runBreachedAccountCheck(
	ctx context.Context,
	stdin io.Reader,
	policy exposure.AccessPolicy,
	apiKeyEnvironment string,
	dependencies agentDependencies,
) (breachedAccountCheckEnvelope, error) {
	if err := validateEnvironmentVariableName(apiKeyEnvironment); err != nil {
		return breachedAccountCheckEnvelope{}, err
	}
	apiKey := disabledBreachedAccountAPIKey
	if policy.Enabled && !policy.Offline {
		var exists bool
		apiKey, exists = dependencies.LookupEnv(apiKeyEnvironment)
		if !exists {
			return breachedAccountCheckEnvelope{},
				errors.New("breached-account API key is unavailable or invalid")
		}
	}
	client, err := exposure.NewBreachedAccountClient(exposure.BreachedAccountConfig{
		Policy: policy,
		HTTP:   dependencies.BreachedAccountHTTP,
		APIKey: apiKey,
	})
	if err != nil {
		return breachedAccountCheckEnvelope{}, err
	}
	email, err := readOneSensitiveInput(stdin, maxEmailInputBytes, "email")
	if err != nil {
		return breachedAccountCheckEnvelope{}, err
	}
	defer zeroBytes(email)

	result, err := client.Check(ctx, string(email))
	if err != nil {
		return breachedAccountCheckEnvelope{}, err
	}
	return breachedAccountCheckEnvelope{
		Schema:        breachedAccountCheckSchema,
		SchemaVersion: securityModeSchemaVersion,
		Contract:      client.Contract(),
		Result:        result,
	}, nil
}

func buildExposureContracts(
	dependencies agentDependencies,
) (exposureContractsEnvelope, error) {
	passwordClient, err := exposure.NewPwnedPasswordsClient(exposure.PwnedPasswordsConfig{
		HTTP: dependencies.PwnedPasswordsHTTP,
	})
	if err != nil {
		return exposureContractsEnvelope{}, err
	}
	accountClient, err := exposure.NewBreachedAccountClient(exposure.BreachedAccountConfig{
		HTTP:   dependencies.BreachedAccountHTTP,
		APIKey: disabledBreachedAccountAPIKey,
	})
	if err != nil {
		return exposureContractsEnvelope{}, err
	}
	contracts := []exposure.AdapterContract{
		passwordClient.Contract(),
		accountClient.Contract(),
	}
	sort.Slice(contracts, func(i, j int) bool {
		return contracts[i].ID < contracts[j].ID
	})
	return exposureContractsEnvelope{
		Schema:        exposureContractsSchema,
		SchemaVersion: securityModeSchemaVersion,
		Contracts:     contracts,
	}, nil
}

func validateSecretRoots(roots []string) ([]string, error) {
	if len(roots) == 0 {
		return nil, errors.New("scan-secrets requires at least one root")
	}
	normalized := make([]string, 0, len(roots))
	for _, root := range roots {
		clean, err := validateLocalPathArgument(root, "secret scan root")
		if err != nil {
			return nil, err
		}
		if isFilesystemRoot(clean) {
			return nil, errors.New("secret scan root must not be a filesystem root")
		}
		info, err := os.Lstat(clean)
		if err != nil {
			return nil, errors.New("secret scan root is unavailable")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("secret scan root must not be a symlink")
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, errors.New("secret scan root must be a directory or regular file")
		}
		normalized = append(normalized, clean)
	}
	return normalized, nil
}

func executableCandidates(paths []string) ([]scanner.ExecutableCandidate, error) {
	if len(paths) == 0 {
		return nil, errors.New("triage-executable requires at least one path")
	}
	candidates := make([]scanner.ExecutableCandidate, 0, len(paths))
	for _, path := range paths {
		clean, err := validateLocalPathArgument(path, "executable path")
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, scanner.ExecutableCandidate{Path: clean})
	}
	return candidates, nil
}

func validateLocalPathArgument(value, label string) (string, error) {
	if value == "" ||
		strings.TrimSpace(value) != value ||
		strings.ContainsRune(value, '\x00') ||
		value == "-" {
		return "", fmt.Errorf("%s is invalid", label)
	}
	clean := filepath.Clean(value)
	if !filepath.IsAbs(value) &&
		(clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator))) {
		return "", fmt.Errorf("%s must not traverse outside the current directory", label)
	}
	return clean, nil
}

func validateFileArgument(value, label string) error {
	clean, err := validateLocalPathArgument(value, label)
	if err != nil {
		return err
	}
	if isFilesystemRoot(clean) {
		return fmt.Errorf("%s must name a file", label)
	}
	return nil
}

func isFilesystemRoot(path string) bool {
	volume := filepath.VolumeName(path)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	return filepath.Clean(path) == root
}

func loadOrCreateFingerprintKey(path string, random io.Reader) ([]byte, error) {
	if random == nil {
		return nil, errors.New("fingerprint key randomness is unavailable")
	}
	key, err := readFingerprintKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("fingerprint key file is unsafe or invalid")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, errors.New("create fingerprint key directory")
	}

	key = make([]byte, fingerprintKeyBytes)
	if _, err := io.ReadFull(random, key); err != nil {
		zeroBytes(key)
		return nil, errors.New("generate fingerprint key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		zeroBytes(key)
		existing, readErr := readFingerprintKey(path)
		if readErr != nil {
			return nil, errors.New("fingerprint key file is unsafe or invalid")
		}
		return existing, nil
	}
	if err != nil {
		zeroBytes(key)
		return nil, errors.New("create fingerprint key file")
	}
	writeErr := writeFingerprintKey(file, path, key)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		zeroBytes(key)
		return nil, errors.New("persist fingerprint key")
	}
	return key, nil
}

func writeFingerprintKey(file *os.File, path string, key []byte) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	written, err := file.Write(key)
	if err != nil {
		return err
	}
	if written != len(key) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !secureFingerprintKeyMode(info.Mode()) ||
		!secureFingerprintKeyMode(pathInfo.Mode()) ||
		!os.SameFile(info, pathInfo) {
		return errors.New("fingerprint key permissions are invalid")
	}
	return nil
}

func readFingerprintKey(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !secureFingerprintKeyMode(before.Mode()) {
		return nil, errors.New("fingerprint key metadata is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !secureFingerprintKeyMode(opened.Mode()) ||
		!secureFingerprintKeyMode(after.Mode()) ||
		!os.SameFile(before, opened) ||
		!os.SameFile(after, opened) {
		return nil, errors.New("fingerprint key changed while opening")
	}
	key, err := io.ReadAll(io.LimitReader(file, fingerprintKeyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(key) != fingerprintKeyBytes {
		zeroBytes(key)
		return nil, errors.New("fingerprint key length is invalid")
	}
	return key, nil
}

func secureFingerprintKeyMode(mode os.FileMode) bool {
	return mode.IsRegular() &&
		mode&os.ModeSymlink == 0 &&
		mode.Perm() == 0o600 &&
		mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func readOneSensitiveInput(
	reader io.Reader,
	maxBytes int,
	label string,
) ([]byte, error) {
	if reader == nil || maxBytes < 1 {
		return nil, fmt.Errorf("%s input is invalid", label)
	}
	value, err := io.ReadAll(io.LimitReader(reader, int64(maxBytes+3)))
	if err != nil {
		return nil, fmt.Errorf("read %s input", label)
	}
	if len(value) > maxBytes+2 {
		zeroBytes(value)
		return nil, fmt.Errorf("%s input exceeds the maximum length", label)
	}
	switch {
	case len(value) >= 2 &&
		value[len(value)-2] == '\r' &&
		value[len(value)-1] == '\n':
		value = value[:len(value)-2]
	case len(value) >= 1 && value[len(value)-1] == '\n':
		value = value[:len(value)-1]
	}
	if len(value) == 0 ||
		len(value) > maxBytes ||
		!utf8.Valid(value) ||
		bytes.IndexByte(value, '\x00') >= 0 ||
		bytes.IndexByte(value, '\r') >= 0 ||
		bytes.IndexByte(value, '\n') >= 0 {
		zeroBytes(value)
		return nil, fmt.Errorf("%s input must contain exactly one valid value", label)
	}
	return value, nil
}

func validateEnvironmentVariableName(name string) error {
	if name == "" ||
		len(name) > maxEnvironmentVariableNameBytes ||
		!isEnvironmentVariableStart(name[0]) {
		return errors.New("HIBP API key environment variable name is invalid")
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if !isEnvironmentVariableStart(character) &&
			(character < '0' || character > '9') {
			return errors.New("HIBP API key environment variable name is invalid")
		}
	}
	return nil
}

func isEnvironmentVariableStart(character byte) bool {
	return character == '_' ||
		character >= 'A' && character <= 'Z' ||
		character >= 'a' && character <= 'z'
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
