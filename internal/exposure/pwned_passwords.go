package exposure

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required by the HIBP k-anonymity protocol.
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
)

const defaultPwnedPasswordsURL = "https://api.pwnedpasswords.com/range"

type PwnedPasswordsConfig struct {
	Policy AccessPolicy
	HTTP   HTTPOptions
}

type PwnedPasswordsClient struct {
	policy   AccessPolicy
	runtime  httpRuntime
	contract AdapterContract
}

type PasswordResult struct {
	State       ResultState        `json:"state"`
	PwnedCount  uint64             `json:"pwned_count,omitempty"`
	Unsupported *UnsupportedResult `json:"unsupported,omitempty"`
}

var _ Adapter = (*PwnedPasswordsClient)(nil)

func NewPwnedPasswordsClient(config PwnedPasswordsConfig) (*PwnedPasswordsClient, error) {
	runtime, err := newHTTPRuntime(AdapterPwnedPasswords, defaultPwnedPasswordsURL, config.HTTP)
	if err != nil {
		return nil, err
	}
	contract := AdapterContract{
		ID:       AdapterPwnedPasswords,
		Endpoint: runtime.endpoint(),
		Method:   http.MethodGet,
		DisclosedData: []DisclosureItem{{
			Field:    "password_sha1_prefix",
			Form:     "first 5 uppercase hexadecimal characters of SHA-1(password); the password and remaining 35 characters are not sent",
			Location: "URL path",
		}},
		Credential: CredentialDisclosure{
			Required: false,
			Scope:    "none",
			Location: "none",
		},
		RetentionAssumption: "HIBP may retain request metadata under its published policies; this adapter does not write the password, hash, prefix, suffix, or response to local storage",
		Offline: OfflineBehavior{
			Supported: false,
			Behavior:  "returns a typed offline_mode unsupported result without making a network request",
		},
	}
	if err := contract.Validate(); err != nil {
		return nil, configurationError(AdapterPwnedPasswords)
	}
	return &PwnedPasswordsClient{
		policy:   config.Policy,
		runtime:  runtime,
		contract: contract,
	}, nil
}

func (client *PwnedPasswordsClient) ID() string {
	return AdapterPwnedPasswords
}

func (client *PwnedPasswordsClient) Contract() AdapterContract {
	contract := client.contract
	contract.DisclosedData = append([]DisclosureItem(nil), client.contract.DisclosedData...)
	return contract
}

// Check hashes password locally. The client does not retain either the
// caller-owned password or the full hash after this call returns.
func (client *PwnedPasswordsClient) Check(ctx context.Context, password string) (PasswordResult, error) {
	if unsupported := gate(client.policy, client.ID()); unsupported != nil {
		return PasswordResult{State: ResultUnsupported, Unsupported: unsupported}, nil
	}

	passwordBytes := []byte(password)
	hash := sha1.Sum(passwordBytes)
	for index := range passwordBytes {
		passwordBytes[index] = 0
	}

	var encoded [sha1.Size * 2]byte
	hex.Encode(encoded[:], hash[:])
	for index := range encoded {
		if encoded[index] >= 'a' && encoded[index] <= 'f' {
			encoded[index] -= 'a' - 'A'
		}
	}
	prefix := string(encoded[:5])
	targetSuffix := append([]byte(nil), encoded[5:]...)
	defer func() {
		for index := range hash {
			hash[index] = 0
		}
		for index := range encoded {
			encoded[index] = 0
		}
		for index := range targetSuffix {
			targetSuffix[index] = 0
		}
	}()

	request, cancel, err := client.runtime.newGETRequest(ctx, prefix)
	if err != nil {
		return PasswordResult{}, err
	}
	defer cancel()
	request.Header.Set("Accept", "text/plain")
	request.Header.Set("Add-Padding", "true")
	request.Header.Set("User-Agent", "oh-my-safety")

	response, err := client.runtime.do(request)
	if err != nil {
		return PasswordResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return PasswordResult{}, statusError(client.ID(), response)
	}
	body, err := client.runtime.readResponse(response)
	if err != nil {
		return PasswordResult{}, err
	}
	count, found, err := parsePwnedPasswordResponse(body, targetSuffix)
	if err != nil {
		return PasswordResult{}, &AdapterError{
			Adapter: client.ID(),
			Kind:    ErrorResponse,
		}
	}
	if !found || count == 0 {
		return PasswordResult{State: ResultNotFound}, nil
	}
	return PasswordResult{State: ResultFound, PwnedCount: count}, nil
}

func parsePwnedPasswordResponse(body, targetSuffix []byte) (uint64, bool, error) {
	if len(body) == 0 {
		return 0, false, ErrAdapter
	}
	var (
		found      bool
		foundCount uint64
		validLines int
	)
	for _, rawLine := range bytes.Split(body, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		separator := bytes.IndexByte(line, ':')
		if separator != 35 || bytes.IndexByte(line[separator+1:], ':') >= 0 {
			return 0, false, ErrAdapter
		}
		suffix := line[:separator]
		if !validHex(suffix) {
			return 0, false, ErrAdapter
		}
		countText := strings.TrimSpace(string(line[separator+1:]))
		count, err := strconv.ParseUint(countText, 10, 64)
		if err != nil {
			return 0, false, ErrAdapter
		}
		validLines++
		if bytes.EqualFold(suffix, targetSuffix) {
			if found {
				return 0, false, ErrAdapter
			}
			found = true
			foundCount = count
		}
	}
	if validLines == 0 {
		return 0, false, ErrAdapter
	}
	return foundCount, found, nil
}

func validHex(value []byte) bool {
	for _, character := range value {
		if character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'f' ||
			character >= 'A' && character <= 'F' {
			continue
		}
		return false
	}
	return true
}
