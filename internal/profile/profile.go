package profile

import (
	"errors"
	"fmt"
)

const (
	Schema        = "io.oh-my-safety/profile"
	SchemaVersion = 1
)

type Workload string

const (
	WorkloadWorkstation Workload = "workstation"
	WorkloadDeveloper   Workload = "developer"
	WorkloadServer      Workload = "server"
)

func (value Workload) valid() bool {
	switch value {
	case WorkloadWorkstation, WorkloadDeveloper, WorkloadServer:
		return true
	default:
		return false
	}
}

type Protection string

const (
	ProtectionBalanced Protection = "balanced"
	ProtectionStrict   Protection = "strict"
)

func (value Protection) valid() bool {
	switch value {
	case ProtectionBalanced, ProtectionStrict:
		return true
	default:
		return false
	}
}

type Management string

const (
	ManagementStandalone Management = "standalone"
	ManagementManaged    Management = "managed"
)

func (value Management) valid() bool {
	switch value {
	case ManagementStandalone, ManagementManaged:
		return true
	default:
		return false
	}
}

type Connectivity string

const (
	ConnectivityConnected Connectivity = "connected"
	ConnectivityOffline   Connectivity = "offline"
	ConnectivityAirGapped Connectivity = "airgapped"
)

func (value Connectivity) valid() bool {
	switch value {
	case ConnectivityConnected, ConnectivityOffline, ConnectivityAirGapped:
		return true
	default:
		return false
	}
}

type Axes struct {
	Workload     Workload     `json:"workload"`
	Protection   Protection   `json:"protection"`
	Management   Management   `json:"management"`
	Connectivity Connectivity `json:"connectivity"`
}

func (axes Axes) Validate() error {
	switch {
	case !axes.Workload.valid():
		return fmt.Errorf("invalid workload axis %q", axes.Workload)
	case !axes.Protection.valid():
		return fmt.Errorf("invalid protection axis %q", axes.Protection)
	case !axes.Management.valid():
		return fmt.Errorf("invalid management axis %q", axes.Management)
	case !axes.Connectivity.valid():
		return fmt.Errorf("invalid connectivity axis %q", axes.Connectivity)
	default:
		return nil
	}
}

type Profile struct {
	Schema        string `json:"schema"`
	SchemaVersion int    `json:"schema_version"`
	Preset        string `json:"preset"`
	Axes          Axes   `json:"axes"`
}

func (profile Profile) Validate() error {
	switch {
	case profile.Schema != Schema:
		return fmt.Errorf("unsupported profile schema %q", profile.Schema)
	case profile.SchemaVersion != SchemaVersion:
		return fmt.Errorf("unsupported profile schema version %d", profile.SchemaVersion)
	case profile.Preset == "":
		return errors.New("profile preset is required")
	default:
		return profile.Axes.Validate()
	}
}

type Patch struct {
	Workload     *Workload     `json:"workload,omitempty"`
	Protection   *Protection   `json:"protection,omitempty"`
	Management   *Management   `json:"management,omitempty"`
	Connectivity *Connectivity `json:"connectivity,omitempty"`
}

type Capabilities struct {
	AllowNetworkEnrichment      bool `json:"allow_network_enrichment"`
	AllowExternalNotifications  bool `json:"allow_external_notifications"`
	AllowAutomaticRemediation   bool `json:"allow_automatic_remediation"`
	RequireSignedOfflineBundles bool `json:"require_signed_offline_bundles"`
	CentrallyManaged            bool `json:"centrally_managed"`
}

const (
	PresetPersonalBalanced       = "personal-balanced"
	PresetPersonalStrict         = "personal-strict"
	PresetDeveloper              = "developer"
	PresetManagedWorkstation     = "managed-workstation"
	PresetManagedServer          = "managed-server"
	PresetAirGappedHighAssurance = "airgapped-high-assurance"

	// Compatibility aliases for the first unreleased agent-core prototype.
	PresetPersonal            = PresetPersonalBalanced
	PresetHighAssuranceAirGap = PresetAirGappedHighAssurance
)

var presets = map[string]Axes{
	PresetPersonalBalanced: {
		Workload:     WorkloadWorkstation,
		Protection:   ProtectionBalanced,
		Management:   ManagementStandalone,
		Connectivity: ConnectivityConnected,
	},
	PresetPersonalStrict: {
		Workload:     WorkloadWorkstation,
		Protection:   ProtectionStrict,
		Management:   ManagementStandalone,
		Connectivity: ConnectivityConnected,
	},
	PresetDeveloper: {
		Workload:     WorkloadDeveloper,
		Protection:   ProtectionStrict,
		Management:   ManagementStandalone,
		Connectivity: ConnectivityConnected,
	},
	PresetManagedWorkstation: {
		Workload:     WorkloadWorkstation,
		Protection:   ProtectionStrict,
		Management:   ManagementManaged,
		Connectivity: ConnectivityConnected,
	},
	PresetManagedServer: {
		Workload:     WorkloadServer,
		Protection:   ProtectionStrict,
		Management:   ManagementManaged,
		Connectivity: ConnectivityConnected,
	},
	PresetAirGappedHighAssurance: {
		Workload:     WorkloadWorkstation,
		Protection:   ProtectionStrict,
		Management:   ManagementStandalone,
		Connectivity: ConnectivityAirGapped,
	},
}

func Resolve(preset string, patches ...Patch) (Profile, error) {
	axes, ok := presets[preset]
	if !ok {
		return Profile{}, fmt.Errorf("unknown profile preset %q", preset)
	}
	for _, patch := range patches {
		if patch.Workload != nil {
			axes.Workload = *patch.Workload
		}
		if patch.Protection != nil {
			axes.Protection = *patch.Protection
		}
		if patch.Management != nil {
			axes.Management = *patch.Management
		}
		if patch.Connectivity != nil {
			axes.Connectivity = *patch.Connectivity
		}
	}
	resolved := Profile{
		Schema:        Schema,
		SchemaVersion: SchemaVersion,
		Preset:        preset,
		Axes:          axes,
	}
	if err := resolved.Validate(); err != nil {
		return Profile{}, err
	}
	return resolved, nil
}

func (profile Profile) Capabilities() Capabilities {
	connected := profile.Axes.Connectivity == ConnectivityConnected
	return Capabilities{
		AllowNetworkEnrichment:     connected,
		AllowExternalNotifications: connected,
		// A profile can require stricter behavior, but selecting one never
		// constitutes authorization for an automatic state-changing action.
		AllowAutomaticRemediation:   false,
		RequireSignedOfflineBundles: profile.Axes.Connectivity == ConnectivityAirGapped,
		CentrallyManaged:            profile.Axes.Management == ManagementManaged,
	}
}

func Presets() []string {
	return []string{
		PresetPersonalBalanced,
		PresetPersonalStrict,
		PresetDeveloper,
		PresetManagedWorkstation,
		PresetManagedServer,
		PresetAirGappedHighAssurance,
	}
}
