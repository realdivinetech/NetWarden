package gatewayauth

import (
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/config"
)

func recordTarget() Target {
	return Target{IP: "192.168.100.1", LocalIP: "192.168.100.7", MAC: "DC:EC:9A:C9:CA:E0"}
}

func TestNewRecordVerifiesItsOwnGateway(t *testing.T) {
	target := recordTarget()
	record, err := NewRecord(target, "huawei-ont", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !Matches(&record, target) {
		t.Fatal("record should match the gateway it was created for")
	}
	if !CheckProof(&record, target) {
		t.Fatal("proof should validate against the original identity")
	}
	if record.Verified != true || record.Strategy != "huawei-ont" || record.GatewayMAC != "dc:ec:9a:c9:ca:e0" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestMatchesRejectsChangedGateway(t *testing.T) {
	target := recordTarget()
	record, err := NewRecord(target, "huawei-ont", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	other := target
	other.IP = "192.168.1.1"
	if Matches(&record, other) {
		t.Fatal("a different gateway IP must not match")
	}

	other = target
	other.MAC = "aa:bb:cc:dd:ee:ff"
	if Matches(&record, other) {
		t.Fatal("a different gateway MAC must not match")
	}

	unknown := target
	unknown.MAC = ""
	if !Matches(&record, unknown) {
		t.Fatal("an unknown MAC on the current side should not invalidate the record")
	}

	unchanged := target
	unchanged.LocalIP = "192.168.100.200"
	if !Matches(&record, unchanged) {
		t.Fatal("DHCP churn on the local address must not invalidate the record")
	}

	if Matches(nil, target) || Matches(&record, Target{}) {
		t.Fatal("empty inputs must not match")
	}
}

func TestCheckProofRefusesTampering(t *testing.T) {
	target := recordTarget()
	record, err := NewRecord(target, "huawei-ont", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tamperedProof := record
	raw, err := base64.StdEncoding.DecodeString(record.Proof)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	tamperedProof.Proof = base64.StdEncoding.EncodeToString(raw)
	if CheckProof(&tamperedProof, target) {
		t.Fatal("tampered proof must fail")
	}

	tamperedSecret := record
	raw, err = base64.StdEncoding.DecodeString(record.Secret)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 0xff
	tamperedSecret.Secret = base64.StdEncoding.EncodeToString(raw)
	if CheckProof(&tamperedSecret, target) {
		t.Fatal("tampered secret must fail")
	}

	other := target
	other.IP = "192.168.1.1"
	if CheckProof(&record, other) {
		t.Fatal("proof must be bound to the gateway identity")
	}

	empty := config.GatewayAuthRecord{}
	if CheckProof(&empty, target) || Matches(&empty, target) {
		t.Fatal("an empty record must fail every check")
	}
}

func TestRecordSurvivesConfigRoundTrip(t *testing.T) {
	target := recordTarget()
	record, err := NewRecord(target, "huawei-ont", true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := config.NewStore(filepath.Join(t.TempDir(), "config.json"))
	if _, err := store.SetGatewayAuth(&record); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GatewayAuth == nil {
		t.Fatal("record did not persist")
	}
	if !Matches(loaded.GatewayAuth, target) || !CheckProof(loaded.GatewayAuth, target) {
		t.Fatalf("persisted record failed validation: %#v", loaded.GatewayAuth)
	}
}
