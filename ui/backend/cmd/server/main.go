// Command server runs the OpenLDAP management UI: a Go HTTP server that
// serves the built React SPA and a small JSON API backed directly by LDAP
// (see internal/ldapclient) — no separate database, no privileged service
// account.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dasomel/ldapium/ui/backend/internal/config"
	"github.com/dasomel/ldapium/ui/backend/internal/httpapi"
	"github.com/dasomel/ldapium/ui/backend/internal/ldapclient"
	"github.com/dasomel/ldapium/ui/backend/internal/session"
	"github.com/dasomel/ldapium/ui/backend/web"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// The final image is distroless static: no shell, no curl, nothing a
	// Docker HEALTHCHECK could call. Kubernetes does not need this — the
	// chart gives the Deployment an httpGet probe — but a `docker run` or
	// docker compose deployment otherwise has no health signal for the UI at
	// all, which is the deployment path this project documents for people
	// without a cluster. So the binary checks itself.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		if err := healthcheck(cfg.ListenAddr); err != nil {
			fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
			os.Exit(1)
		}
		return
	}

	spa, err := web.DistFS()
	if err != nil {
		log.Fatalf("embedded frontend: %v", err)
	}

	dialer := ldapclient.NewDialer(cfg)
	sessions := session.NewStore(cfg.SessionTTL)

	janitorCtx, stopJanitor := context.WithCancel(context.Background())
	defer stopJanitor()
	go sessions.RunJanitor(janitorCtx, time.Minute)

	srv, err := httpapi.New(cfg, dialer, sessions, spa)
	if err != nil {
		log.Fatalf("initialize HTTP server: %v", err)
	}

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("listening on %s", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	stopJanitor()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

// healthcheck asks the running server the same question the Kubernetes
// readiness probe does. /api/auth/config answers from configuration alone —
// no LDAP round-trip — so this reports on the process, not on the directory:
// a UI that cannot reach the directory should still be up and say so.
func healthcheck(listenAddr string) error {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", listenAddr, err)
	}
	// A wildcard bind (":8080", "0.0.0.0:8080") is not an address to dial.
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/api/auth/config"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return nil
}
