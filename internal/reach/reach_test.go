package reach

import (
	"errors"
	"testing"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

type fakeMembers struct {
	byScope map[string][]string
	calls   int
}

func (f *fakeMembers) SubscriptionMembers(tenantID, subsAccID string) ([]string, error) {
	f.calls++
	return f.byScope[tenantID+"/"+subsAccID], nil
}

var caller = actor.Tuple{
	TenantID:  "t1",
	SubsAccID: "s1",
	Role:      "alpha",
	UserAccID: "alice",
}

func members() *fakeMembers {
	return &fakeMembers{byScope: map[string][]string{"t1/s1": {"alice", "bob"}}}
}

func TestSelfAndOwnSubscriptionAreReachable(t *testing.T) {
	for _, addr := range []string{
		actor.PersonID("alice"),
		actor.ServiceID("alice"),
		actor.SubscriptionGroupID("s1"),
		actor.ServiceID("bob"), // shares the subscription
	} {
		if err := Check(caller, members(), []string{addr}, Options{}); err != nil {
			t.Errorf("%s should be reachable: %v", addr, err)
		}
	}
}

// TestTenantScopeRefusedFromAgentToken pins the design's strictest consequence:
// an agent cannot broadcast tenant-wide AT ALL. Its MCP token proves one
// subscription; a workspace under one subscription does not license the tenant.
func TestTenantScopeRefusedFromAgentToken(t *testing.T) {
	err := Check(caller, members(), []string{actor.TenantGroupID("t1")}, Options{})
	if err == nil {
		t.Fatal("an agent addressed the tenant group; it cannot prove it is licensed on the tenant")
	}
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a Refusal naming the addressee, got %T", err)
	}
	if ref.Addressee != actor.TenantGroupID("t1") {
		t.Errorf("refusal named %q, want the tenant group", ref.Addressee)
	}
}

// The same address IS reachable once a real mycelium profile says so. Only the
// human path may set this.
func TestTenantScopeAllowedForALicensedHuman(t *testing.T) {
	if err := Check(caller, members(), []string{actor.TenantGroupID("t1")}, Options{TenantLicensed: true}); err != nil {
		t.Fatalf("a licensed human should reach the tenant group: %v", err)
	}
}

func TestAnotherTenantIsNeverReachable(t *testing.T) {
	if err := Check(caller, members(), []string{actor.TenantGroupID("t2")}, Options{TenantLicensed: true}); err == nil {
		t.Fatal("reached a tenant group that is not the caller's own, even with TenantLicensed")
	}
}

func TestForeignSubscriptionIsRefused(t *testing.T) {
	if err := Check(caller, members(), []string{actor.SubscriptionGroupID("s2")}, Options{}); err == nil {
		t.Fatal("reached a subscription the caller is not licensed on")
	}
}

func TestStrangerIsRefused(t *testing.T) {
	err := Check(caller, members(), []string{actor.ServiceID("mallory")}, Options{})
	if err == nil {
		t.Fatal("reached an actor with no workspace under a shared subscription")
	}
	var ref *Refusal
	if !errors.As(err, &ref) || ref.Addressee != actor.ServiceID("mallory") {
		t.Fatalf("refusal must name the offending addressee, got %v", err)
	}
}

// TestOutOfReachAddresseeRefusesWholeActivity is the invariant that makes the
// rest safe. Trimming the audience to the reachable subset would let an author
// believe a memory is shared when it is not, and they would stop looking.
func TestOutOfReachAddresseeRefusesWholeActivity(t *testing.T) {
	audience := []string{
		actor.ServiceID("bob"),          // reachable
		actor.SubscriptionGroupID("s1"), // reachable
		actor.ServiceID("mallory"),      // NOT reachable
	}
	err := Check(caller, members(), audience, Options{})
	if err == nil {
		t.Fatal("a mixed audience was accepted; the whole activity must be refused")
	}
	var ref *Refusal
	if !errors.As(err, &ref) {
		t.Fatalf("want a Refusal, got %T", err)
	}
	if ref.Addressee != actor.ServiceID("mallory") {
		t.Errorf("named %q, want the one unreachable entry", ref.Addressee)
	}
}

func TestEmptyAudienceIsPrivateAndAllowed(t *testing.T) {
	if err := Check(caller, members(), nil, Options{}); err != nil {
		t.Fatalf("an unaddressed publish is private to the author, not an error: %v", err)
	}
}

func TestIncompleteTupleIsRefused(t *testing.T) {
	if err := Check(actor.Tuple{TenantID: "t1"}, members(), []string{actor.PersonID("alice")}, Options{}); err == nil {
		t.Fatal("a partial tuple was accepted; a blank dimension would address a different shard")
	}
}

func TestNonMangroveIdentityIsRefused(t *testing.T) {
	for _, addr := range []string{"https://mastodon.example/users/bob", "alice@example.com", "*", ""} {
		if err := Check(caller, members(), []string{addr}, Options{}); err == nil {
			t.Errorf("%q was accepted as an addressee", addr)
		}
	}
}

// The member list crosses a process boundary, so it must not be fetched for an
// audience that never needs it.
func TestMemberLookupIsSkippedWhenUnneeded(t *testing.T) {
	m := members()
	if err := Check(caller, m, []string{actor.SubscriptionGroupID("s1")}, Options{}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if m.calls != 0 {
		t.Errorf("looked up members %d times for an audience that did not need it", m.calls)
	}
}
