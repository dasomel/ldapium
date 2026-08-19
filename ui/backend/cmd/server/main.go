// Command server runs the OpenLDAP management UI: a Go HTTP server that
// serves the built React SPA and a small JSON API backed directly by LDAP
// (see internal/ldapclient) — no separate database, no privileged service
// account.
package main

import (
	"context"
	"log"
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
