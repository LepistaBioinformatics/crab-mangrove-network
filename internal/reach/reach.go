// Package reach is the containment invariant, and it is deliberately the only
// place that implements it.
//
// THE RULE: no share crosses a boundary the sharer's own permissions do not
// already reach. Every widening verb -- Create, Update, Add, Announce -- calls
// Check before anything is written. A second enforcement site would be a second
// thing to forget when a fifth addressing dimension is added, so there is one
// function and a test that asserts each verb routes through it.
//
// WHY THE AGENT PATH IS SO NARROW. An agent reaches the mangrove through
// crab-shell-proxy, authenticated by the stateless MCP token, which signs
// tenantID/subsAccID/role/userAccID and carries NO mycelium LicensedResources.
// So the caller's own subscription is provable and nothing else is. Rather than
// fetch a profile the agent never presented, the gate treats that as the bound:
//
//	own actors ............................ allowed, the tuple names them
//	an actor with a workspace in the same
//	  (tenant, subscription) .............. allowed, the proxy can enumerate them
//	the subscription Group ................ allowed, the tuple names it
//	the tenant Group ...................... REFUSED on the agent path
//	anything else ......................... refused, not provable
//
// A workspace under one subscription does not license the whole tenant, and the
// token cannot prove otherwise. The consequence is stricter than the
// specification demanded and better than it: AN AGENT CANNOT BROADCAST
// TENANT-WIDE AT ALL. A turn steered by untrusted text reaching every member of
// a tenant is the shape this stack refuses elsewhere for the same reason.
//
// Tenant scope is therefore a human action, taken in the webapp, where the
// request carries a real mycelium profile through the gateway and the caller's
// tier can be resolved properly. That path sets Options.TenantLicensed, and it
// is the ONLY thing that may set it.
package reach

import (
	"fmt"
	"strings"

	"github.com/LepistaBioinformatics/crab-mangrove-network/internal/actor"
)

// Members supplies the one membership fact the gate needs. In production it is
// backed by crab-shell-proxy's ListSubscriptionUsers, which globs the workspace
// tree -- the mangrove holds no membership list of its own, so it cannot disagree
// with mycelium.
type Members interface {
	SubscriptionMembers(tenantID, subsAccID string) ([]string, error)
}

// Options carries facts the agent path cannot prove. Only a request that
// arrived with a verified mycelium profile may set these.
type Options struct {
	// TenantLicensed means the caller is licensed on Tuple.TenantID, as
	// resolved from a real profile. Never set from an agent's MCP token.
	TenantLicensed bool
}

// Refusal names the addressee that failed and why. It is an error rather than a
// filter result on purpose: see Check.
type Refusal struct {
	Addressee string
	Reason    string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("out of reach: %s (%s)", r.Addressee, r.Reason)
}

// Check decides whether every addressee is within the caller's reach.
//
// IT REFUSES THE WHOLE ACTIVITY, and never trims the audience down to the
// reachable subset. Dropping the unreachable entries and delivering to the rest
// would leave the author believing a memory is shared when it is not, and a
// silent partial share is worse than a refused one: the author stops looking
// for the problem.
func Check(t actor.Tuple, m Members, audience []string, opt Options) error {
	if !t.Valid() {
		return &Refusal{Addressee: "<caller>", Reason: "incomplete workspace tuple"}
	}
	if len(audience) == 0 {
		return nil // private to the author; the default a bare publish means
	}

	ownPerson := actor.PersonID(t.UserAccID)
	ownService := actor.ServiceID(t.UserAccID)
	ownSubscription := actor.SubscriptionGroupID(t.SubsAccID)
	ownTenant := actor.TenantGroupID(t.TenantID)

	// Resolved lazily: most audiences are self or own-subscription and never
	// need the member list, and the lookup crosses a process boundary.
	var members map[string]bool

	for _, addr := range audience {
		switch {
		case addr == ownPerson || addr == ownService:
			continue

		case addr == ownSubscription:
			continue

		case addr == ownTenant:
			if opt.TenantLicensed {
				continue
			}
			return &Refusal{
				Addressee: addr,
				Reason:    "tenant scope needs a licensed human; an agent token proves one subscription, not the tenant",
			}

		case strings.HasPrefix(addr, "mangrove:group:"):
			return &Refusal{Addressee: addr, Reason: "not a scope this caller is licensed on"}

		case actor.AccIDOf(addr) != "":
			if members == nil {
				list, err := m.SubscriptionMembers(t.TenantID, t.SubsAccID)
				if err != nil {
					return fmt.Errorf("reach: resolve subscription members: %w", err)
				}
				members = make(map[string]bool, len(list))
				for _, acc := range list {
					members[acc] = true
				}
			}
			if members[actor.AccIDOf(addr)] {
				continue
			}
			return &Refusal{
				Addressee: addr,
				Reason:    "no workspace under a subscription this caller shares",
			}

		default:
			return &Refusal{Addressee: addr, Reason: "not an addressable mangrove identity"}
		}
	}
	return nil
}
