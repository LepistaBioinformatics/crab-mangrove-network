// Command crab-reef-network runs the reef: a federated memory network for
// zombie-crab agents.
//
// EXPERIMENTAL. See the README. Interfaces, the on-disk format and the
// activity vocabulary may change without a migration path.
//
// It listens on an internal network and expects exactly one caller,
// crab-shell-proxy, which has already authenticated the agent or human making
// the request. There is no public route and no federation in this version.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LepistaBioinformatics/crab-reef-network/internal/actor"
	"github.com/LepistaBioinformatics/crab-reef-network/internal/httpapi"
	"github.com/LepistaBioinformatics/crab-reef-network/internal/reeflog"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("crab-reef-network stopped", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	listen := env("REEF_LISTEN", ":8090")
	storeDir := env("REEF_STORE_DIR", "/data/reef")
	proxyURL := env("REEF_PROXY_BASE_URL", "http://crab-shell-proxy:8080")

	// REFUSE TO BOOT WITHOUT A TOKEN, naming the variable.
	//
	// The opposite choice -- start, and let every request fail 401 -- looks
	// safe and is worse: an operator sees a running container and a reachable
	// port, and discovers the misconfiguration later, from a member. A gate
	// with no credential behind it is the shape this stack refuses elsewhere.
	token := os.Getenv("REEF_TOKEN")
	if token == "" {
		return errors.New("REEF_TOKEN is unset: the reef has exactly one caller and will not listen without the shared secret that proves it")
	}

	actors, err := actor.NewStore(storeDir)
	if err != nil {
		return err
	}
	rlog, err := reeflog.New(storeDir)
	if err != nil {
		return err
	}

	srv := &httpapi.Server{
		Actors:  actors,
		Log:     rlog,
		Members: &proxyMembers{base: proxyURL, token: token, client: &http.Client{Timeout: 10 * time.Second}},
		Token:   token,
		Logger:  log,
	}

	h := &http.Server{
		Addr:              listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("reef listening", "addr", listen, "store", storeDir, "experimental", true)
		if err := h.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return h.Shutdown(shutdownCtx)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// proxyMembers answers the one membership question the reachability gate asks,
// by calling crab-shell-proxy.
//
// The reef deliberately keeps NO membership list of its own. A stored list is a
// second source of truth that can disagree with mycelium, and every rule about
// who may address what would then depend on which of the two was consulted.
type proxyMembers struct {
	base   string
	token  string
	client *http.Client
}

func (p *proxyMembers) SubscriptionMembers(tenantID, subsAccID string) ([]string, error) {
	url := fmt.Sprintf("%s/v1/reef/subscription-members?tenant_id=%s&subs_acc_id=%s", p.base, tenantID, subsAccID)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reef: subscription members: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reef: subscription members: proxy answered %d", resp.StatusCode)
	}
	var body struct {
		AccIDs []string `json:"accIds"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("reef: subscription members: %w", err)
	}
	return body.AccIDs, nil
}
