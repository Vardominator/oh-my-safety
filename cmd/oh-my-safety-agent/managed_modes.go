package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/controller"
	"github.com/Vardominator/oh-my-safety/internal/journal"
	"github.com/Vardominator/oh-my-safety/internal/managed"
)

const (
	defaultEnrollmentTokenEnv = "OMS_ENROLLMENT_TOKEN"
	managedStateFileName      = "managed-enrollment.json"
	managedModeSchemaVersion  = 1
	maxFlatPolicyBytes        = 128 << 10

	managedEnrollmentSchema = "io.oh-my-safety/managed-enrollment-result"
	managedSyncSchema       = "io.oh-my-safety/managed-sync-result"
	managedRotationSchema   = "io.oh-my-safety/managed-credential-rotation"
	managedFlatPolicySchema = "io.oh-my-safety/managed-policy-flat"
)

// agentVersion is overridden in release builds with
// -ldflags=-X=main.agentVersion=<version>.
var agentVersion = "development"

type managedEnrollmentResult struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Enrolled      bool   `json:"enrolled"`
	ControllerURL string `json:"controller_url"`
	DeviceID      string `json:"device_id"`
	StatePath     string `json:"state_path"`
}

type managedCredentialRotationResult struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Rotated       bool   `json:"rotated"`
	DeviceID      string `json:"device_id"`
	StatePath     string `json:"state_path"`
}

type managedSyncResult struct {
	Schema        string             `json:"schema"`
	SchemaVersion int                `json:"schema_version"`
	Result        managed.SyncResult `json:"result"`
}

type managedPolicyOutput string

func (output managedPolicyOutput) writeTo(destination io.Writer) error {
	_, err := io.WriteString(destination, string(output))
	return err
}

func defaultManagedStatePath(stateDB string) (string, error) {
	if err := validateFileArgument(stateDB, "state database path"); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(stateDB), managedStateFileName), nil
}

func runManagedEnrollment(
	ctx context.Context,
	statePath string,
	controllerURL string,
	tokenEnvironment string,
	policyPublicKey string,
	deviceName string,
) (managedEnrollmentResult, error) {
	metadata, err := managed.LocalDeviceMetadataForName(agentVersion, deviceName)
	if err != nil {
		return managedEnrollmentResult{}, err
	}
	state, err := managed.EnrollFromEnvironment(ctx, managed.EnrollmentOptions{
		StatePath:       statePath,
		ControllerURL:   controllerURL,
		TokenEnv:        tokenEnvironment,
		PolicyPublicKey: policyPublicKey,
		Metadata:        metadata,
	})
	if err != nil {
		return managedEnrollmentResult{}, err
	}
	return managedEnrollmentResult{
		Schema:        managedEnrollmentSchema,
		SchemaVersion: managedModeSchemaVersion,
		Enrolled:      true,
		ControllerURL: state.ControllerURL,
		DeviceID:      state.DeviceID,
		StatePath:     statePath,
	}, nil
}

func runManagedSync(
	ctx context.Context,
	statePath string,
	stateDB string,
) (managedSyncResult, error) {
	client, err := managed.Open(statePath, nil)
	if err != nil {
		return managedSyncResult{}, err
	}
	metadata, err := managed.LocalDeviceMetadata(agentVersion)
	if err != nil {
		return managedSyncResult{}, err
	}
	store, err := journal.Open(stateDB)
	if err != nil {
		return managedSyncResult{}, err
	}
	result, syncErr := client.Sync(ctx, store, metadata, time.Now().UTC())
	closeErr := store.Close()
	if syncErr != nil {
		return managedSyncResult{}, syncErr
	}
	if closeErr != nil {
		return managedSyncResult{}, errors.New("close local journal after managed sync")
	}
	return managedSyncResult{
		Schema:        managedSyncSchema,
		SchemaVersion: managedModeSchemaVersion,
		Result:        result,
	}, nil
}

func runManagedCredentialRotation(
	ctx context.Context,
	statePath string,
) (managedCredentialRotationResult, error) {
	state, err := managed.LoadState(statePath)
	if err != nil {
		return managedCredentialRotationResult{}, err
	}
	client, err := managed.Open(statePath, nil)
	if err != nil {
		return managedCredentialRotationResult{}, err
	}
	if err := client.RotateCredential(ctx); err != nil {
		return managedCredentialRotationResult{}, err
	}
	return managedCredentialRotationResult{
		Schema:        managedRotationSchema,
		SchemaVersion: managedModeSchemaVersion,
		Rotated:       true,
		DeviceID:      state.DeviceID,
		StatePath:     statePath,
	}, nil
}

func runManagedPolicy(statePath string) (managedPolicyOutput, error) {
	document, err := managed.LoadPolicy(statePath)
	if err != nil {
		return "", err
	}
	checks := append([]controller.PolicyCheck(nil), document.Checks...)
	sort.Slice(checks, func(left, right int) bool {
		return checks[left].ID < checks[right].ID
	})
	var output strings.Builder
	rows := [][]string{
		{"schema", managedFlatPolicySchema, strconv.Itoa(managedModeSchemaVersion)},
		{"policy_id", document.ID},
		{"revision", strconv.FormatUint(document.Revision, 10)},
		{"profile", document.Profile},
		{"cadence_scan_interval_seconds", strconv.FormatUint(
			uint64(document.Cadence.ScanIntervalSeconds),
			10,
		)},
		{"cadence_jitter_seconds", strconv.FormatUint(
			uint64(document.Cadence.JitterSeconds),
			10,
		)},
		{"reporting_enabled", strconv.FormatBool(document.Reporting.Enabled)},
		{"reporting_sync_interval_seconds", strconv.FormatUint(
			uint64(document.Reporting.SyncIntervalSeconds),
			10,
		)},
		{"remediation", string(document.Remediation)},
	}
	for _, row := range rows {
		output.WriteString(strings.Join(row, "\t"))
		output.WriteByte('\n')
	}
	for _, check := range checks {
		output.WriteString("check\t")
		output.WriteString(check.ID)
		output.WriteByte('\t')
		output.WriteString(strconv.FormatBool(check.Enabled))
		output.WriteByte('\n')
	}
	if output.Len() > maxFlatPolicyBytes {
		return "", fmt.Errorf("managed policy output exceeds %d bytes", maxFlatPolicyBytes)
	}
	return managedPolicyOutput(output.String()), nil
}
