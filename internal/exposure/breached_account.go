package exposure

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

const defaultBreachedAccountURL = "https://haveibeenpwned.com/api/v3/breachedaccount"

type BreachedAccountConfig struct {
	Policy    AccessPolicy
	HTTP      HTTPOptions
	APIKey    string
	UserAgent string
}

type BreachedAccountClient struct {
	policy    AccessPolicy
	runtime   httpRuntime
	apiKey    string
	userAgent string
	contract  AdapterContract
}

type Breach struct {
	Name               string   `json:"Name"`
	Title              string   `json:"Title"`
	Domain             string   `json:"Domain"`
	BreachDate         string   `json:"BreachDate"`
	AddedDate          string   `json:"AddedDate"`
	ModifiedDate       string   `json:"ModifiedDate"`
	PwnCount           uint64   `json:"PwnCount"`
	DataClasses        []string `json:"DataClasses"`
	IsVerified         bool     `json:"IsVerified"`
	IsFabricated       bool     `json:"IsFabricated"`
	IsSensitive        bool     `json:"IsSensitive"`
	IsRetired          bool     `json:"IsRetired"`
	IsSpamList         bool     `json:"IsSpamList"`
	IsMalware          bool     `json:"IsMalware"`
	IsStealerLog       bool     `json:"IsStealerLog"`
	IsSubscriptionFree bool     `json:"IsSubscriptionFree"`
}

type BreachedAccountResult struct {
	State       ResultState        `json:"state"`
	Breaches    []Breach           `json:"breaches,omitempty"`
	Unsupported *UnsupportedResult `json:"unsupported,omitempty"`
}

var _ Adapter = (*BreachedAccountClient)(nil)

func NewBreachedAccountClient(config BreachedAccountConfig) (*BreachedAccountClient, error) {
	if !validAPIKey(config.APIKey) {
		return nil, configurationError(AdapterBreachedAccount)
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = "oh-my-safety"
	}
	if strings.ContainsAny(userAgent, "\r\n") || len(userAgent) > 256 {
		return nil, configurationError(AdapterBreachedAccount)
	}
	runtime, err := newHTTPRuntime(AdapterBreachedAccount, defaultBreachedAccountURL, config.HTTP)
	if err != nil {
		return nil, err
	}
	contract := AdapterContract{
		ID:       AdapterBreachedAccount,
		Endpoint: runtime.endpoint(),
		Method:   http.MethodGet,
		DisclosedData: []DisclosureItem{{
			Field:    "monitored_email",
			Form:     "complete caller-provided email address, URL-escaped in transit",
			Location: "URL path",
		}},
		Credential: CredentialDisclosure{
			Required: true,
			Scope:    "HIBP subscription scope granted to the supplied key; this adapter uses it only for breached-account reads",
			Location: "hibp-api-key request header",
		},
		RetentionAssumption: "HIBP may retain the email, API request metadata, and credential metadata under its published policies; this adapter does not write the email or API key to local storage",
		Offline: OfflineBehavior{
			Supported: false,
			Behavior:  "returns a typed offline_mode unsupported result without making a network request",
		},
	}
	if err := contract.Validate(); err != nil {
		return nil, configurationError(AdapterBreachedAccount)
	}
	return &BreachedAccountClient{
		policy:    config.Policy,
		runtime:   runtime,
		apiKey:    config.APIKey,
		userAgent: userAgent,
		contract:  contract,
	}, nil
}

func (client *BreachedAccountClient) ID() string {
	return AdapterBreachedAccount
}

func (client *BreachedAccountClient) Contract() AdapterContract {
	contract := client.contract
	contract.DisclosedData = append([]DisclosureItem(nil), client.contract.DisclosedData...)
	return contract
}

func (client *BreachedAccountClient) Check(
	ctx context.Context,
	email string,
) (BreachedAccountResult, error) {
	if unsupported := gate(client.policy, client.ID()); unsupported != nil {
		return BreachedAccountResult{State: ResultUnsupported, Unsupported: unsupported}, nil
	}
	if !validEmail(email) {
		return BreachedAccountResult{}, inputError(client.ID())
	}

	request, cancel, err := client.runtime.newGETRequest(ctx, email)
	if err != nil {
		return BreachedAccountResult{}, err
	}
	defer cancel()
	query := request.URL.Query()
	query.Set("truncateResponse", "false")
	request.URL.RawQuery = query.Encode()
	request.Header.Set("Accept", "application/json")
	request.Header.Set("hibp-api-key", client.apiKey)
	request.Header.Set("User-Agent", client.userAgent)

	response, err := client.runtime.do(request)
	if err != nil {
		return BreachedAccountResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return BreachedAccountResult{State: ResultNotFound}, nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return BreachedAccountResult{}, statusError(client.ID(), response)
	}
	body, err := client.runtime.readResponse(response)
	if err != nil {
		return BreachedAccountResult{}, err
	}
	var breaches []Breach
	if err := json.Unmarshal(body, &breaches); err != nil {
		return BreachedAccountResult{}, &AdapterError{
			Adapter: client.ID(),
			Kind:    ErrorResponse,
		}
	}
	if breaches == nil {
		return BreachedAccountResult{}, &AdapterError{
			Adapter: client.ID(),
			Kind:    ErrorResponse,
		}
	}
	if len(breaches) == 0 {
		return BreachedAccountResult{State: ResultNotFound}, nil
	}
	for index := range breaches {
		if strings.TrimSpace(breaches[index].Name) == "" {
			return BreachedAccountResult{}, &AdapterError{
				Adapter: client.ID(),
				Kind:    ErrorResponse,
			}
		}
		breaches[index].DataClasses = append([]string(nil), breaches[index].DataClasses...)
	}
	return BreachedAccountResult{State: ResultFound, Breaches: breaches}, nil
}

func validAPIKey(value string) bool {
	return len(value) == 32 && validHex([]byte(value))
}

func validEmail(value string) bool {
	if strings.TrimSpace(value) != value ||
		len(value) < 3 ||
		len(value) > 254 ||
		strings.ContainsAny(value, "/\\?#\r\n\t ") ||
		strings.Count(value, "@") != 1 {
		return false
	}
	parts := strings.SplitN(value, "@", 2)
	return parts[0] != "" && parts[1] != "" && strings.Contains(parts[1], ".")
}
