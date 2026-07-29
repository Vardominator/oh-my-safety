package profile

import (
	"encoding/json"
	"testing"
)

func TestPresetJSONContractAndCapabilities(t *testing.T) {
	resolved, err := Resolve(PresetAirGappedHighAssurance)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":"io.oh-my-safety/profile","schema_version":1,"preset":"airgapped-high-assurance","axes":{"workload":"workstation","protection":"strict","management":"standalone","connectivity":"airgapped"}}`
	if string(got) != want {
		t.Fatalf("profile contract changed\nwant: %s\n got: %s", want, got)
	}

	capabilities := resolved.Capabilities()
	if capabilities.AllowNetworkEnrichment || capabilities.AllowExternalNotifications {
		t.Fatal("air-gapped profile unexpectedly permits network behavior")
	}
	if capabilities.AllowAutomaticRemediation {
		t.Fatal("selecting a profile must not authorize automatic remediation")
	}
	if !capabilities.RequireSignedOfflineBundles || capabilities.CentrallyManaged {
		t.Fatalf("unexpected air-gapped capabilities: %#v", capabilities)
	}
}

func TestProfileAxesComposeIndependently(t *testing.T) {
	connectivity := ConnectivityOffline
	protection := ProtectionBalanced
	resolved, err := Resolve(
		PresetDeveloper,
		Patch{Connectivity: &connectivity},
		Patch{Protection: &protection},
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Axes.Connectivity != ConnectivityOffline {
		t.Fatalf("connectivity = %q", resolved.Axes.Connectivity)
	}
	if resolved.Axes.Protection != ProtectionBalanced {
		t.Fatalf("protection = %q", resolved.Axes.Protection)
	}
	if resolved.Axes.Workload != WorkloadDeveloper ||
		resolved.Axes.Management != ManagementStandalone {
		t.Fatalf("unpatched axes changed: %#v", resolved.Axes)
	}
}

func TestProfilesRejectUnknownPresetsAndInvalidPatches(t *testing.T) {
	if _, err := Resolve("missing"); err == nil {
		t.Fatal("unknown preset accepted")
	}
	invalid := Workload("root-everything")
	if _, err := Resolve(PresetPersonalBalanced, Patch{Workload: &invalid}); err == nil {
		t.Fatal("invalid workload accepted")
	}
}

func TestEveryPresetIsValidAndNamed(t *testing.T) {
	seen := map[string]bool{}
	for _, name := range Presets() {
		if seen[name] {
			t.Fatalf("duplicate preset %q", name)
		}
		seen[name] = true
		resolved, err := Resolve(name)
		if err != nil {
			t.Fatalf("resolve %q: %v", name, err)
		}
		if resolved.Preset != name {
			t.Fatalf("preset name = %q, want %q", resolved.Preset, name)
		}
	}
	if len(seen) != 6 {
		t.Fatalf("got %d presets, want 6", len(seen))
	}
}
