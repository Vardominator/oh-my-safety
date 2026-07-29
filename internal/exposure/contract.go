// Package exposure contains opt-in, local-first adapters for querying external
// exposure services. Every adapter publishes its egress contract before it can
// be enabled.
package exposure

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	AdapterPwnedPasswords  = "hibp-pwned-passwords"
	AdapterBreachedAccount = "hibp-breached-account"
)

type DisclosureItem struct {
	Field    string `json:"field"`
	Form     string `json:"form"`
	Location string `json:"location"`
}

type CredentialDisclosure struct {
	Required bool   `json:"required"`
	Scope    string `json:"scope"`
	Location string `json:"location"`
}

type OfflineBehavior struct {
	Supported bool   `json:"supported"`
	Behavior  string `json:"behavior"`
}

// AdapterContract is the human- and machine-readable trust boundary for an
// external adapter. It intentionally describes provider assumptions rather
// than presenting them as guarantees.
type AdapterContract struct {
	ID                  string               `json:"id"`
	Endpoint            string               `json:"endpoint"`
	Method              string               `json:"method"`
	DisclosedData       []DisclosureItem     `json:"disclosed_data"`
	Credential          CredentialDisclosure `json:"credential"`
	RetentionAssumption string               `json:"retention_assumption"`
	Offline             OfflineBehavior      `json:"offline"`
}

func (contract AdapterContract) Validate() error {
	endpoint, err := url.Parse(contract.Endpoint)
	switch {
	case strings.TrimSpace(contract.ID) == "":
		return errors.New("adapter contract id is required")
	case err != nil || endpoint.Scheme == "" || endpoint.Host == "":
		return errors.New("adapter contract endpoint is invalid")
	case contract.Method != "GET":
		return errors.New("adapter contract method must be GET")
	case len(contract.DisclosedData) == 0:
		return errors.New("adapter contract must declare disclosed data")
	case strings.TrimSpace(contract.Credential.Scope) == "":
		return errors.New("adapter contract credential scope is required")
	case strings.TrimSpace(contract.Credential.Location) == "":
		return errors.New("adapter contract credential location is required")
	case strings.TrimSpace(contract.RetentionAssumption) == "":
		return errors.New("adapter contract retention assumption is required")
	case strings.TrimSpace(contract.Offline.Behavior) == "":
		return errors.New("adapter contract offline behavior is required")
	}
	for _, item := range contract.DisclosedData {
		if strings.TrimSpace(item.Field) == "" ||
			strings.TrimSpace(item.Form) == "" ||
			strings.TrimSpace(item.Location) == "" {
			return errors.New("adapter contract has incomplete disclosure metadata")
		}
	}
	return nil
}

type Adapter interface {
	ID() string
	Contract() AdapterContract
}

type AccessPolicy struct {
	Enabled bool
	Offline bool
}

type ResultState string

const (
	ResultFound       ResultState = "found"
	ResultNotFound    ResultState = "not_found"
	ResultUnsupported ResultState = "unsupported"
)

type UnsupportedReason string

const (
	UnsupportedDisabled UnsupportedReason = "adapter_disabled"
	UnsupportedOffline  UnsupportedReason = "offline_mode"
)

type UnsupportedResult struct {
	Adapter string            `json:"adapter"`
	Reason  UnsupportedReason `json:"reason"`
	Message string            `json:"message"`
}

func gate(policy AccessPolicy, adapter string) *UnsupportedResult {
	if policy.Offline {
		return &UnsupportedResult{
			Adapter: adapter,
			Reason:  UnsupportedOffline,
			Message: "external exposure lookup is unavailable in offline mode",
		}
	}
	if !policy.Enabled {
		return &UnsupportedResult{
			Adapter: adapter,
			Reason:  UnsupportedDisabled,
			Message: "external exposure adapter is not enabled",
		}
	}
	return nil
}

var ErrAdapter = errors.New("exposure adapter error")

type ErrorKind string

const (
	ErrorConfiguration ErrorKind = "configuration"
	ErrorInput         ErrorKind = "input"
	ErrorRequest       ErrorKind = "request"
	ErrorCanceled      ErrorKind = "canceled"
	ErrorResponse      ErrorKind = "response"
	ErrorStatus        ErrorKind = "status"
)

// AdapterError deliberately excludes request URLs, response bodies,
// credentials, account identifiers, and password-derived hash material.
type AdapterError struct {
	Adapter    string
	Kind       ErrorKind
	StatusCode int
	Retryable  bool
	RetryAfter time.Duration

	cause error
}

func (adapterError *AdapterError) Error() string {
	if adapterError.StatusCode > 0 {
		return fmt.Sprintf(
			"%s adapter request failed with HTTP status %d",
			adapterError.Adapter,
			adapterError.StatusCode,
		)
	}
	return fmt.Sprintf("%s adapter %s failed", adapterError.Adapter, adapterError.Kind)
}

func (adapterError *AdapterError) Unwrap() error {
	return adapterError.cause
}

func (adapterError *AdapterError) Is(target error) bool {
	return target == ErrAdapter ||
		target == context.Canceled && errors.Is(adapterError.cause, context.Canceled) ||
		target == context.DeadlineExceeded && errors.Is(adapterError.cause, context.DeadlineExceeded)
}

func configurationError(adapter string) error {
	return &AdapterError{Adapter: adapter, Kind: ErrorConfiguration}
}

func inputError(adapter string) error {
	return &AdapterError{Adapter: adapter, Kind: ErrorInput}
}
