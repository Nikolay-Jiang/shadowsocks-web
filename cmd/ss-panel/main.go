package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/panel"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dataDir := flag.String("data-dir", "data", "data directory")
	dbPath := flag.String("db", "", "SQLite database path (default data-dir/panel.db)")
	publicURL := flag.String("public-url", os.Getenv("SS_PANEL_PUBLIC_URL"), "public panel URL shown in agent config (for example https://panel.example.com)")
	name := flag.String("name", os.Getenv("SS_PANEL_NAME"), "panel display name")
	secureCookie := flag.Bool("secure-cookie", false, "mark the session cookie Secure (enable behind HTTPS)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ss-panel %s\n", protocol.Version)
		return
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ss-panel: ")

	srv, err := panel.New(panel.Config{
		Listen:       *listen,
		DataDir:      *dataDir,
		DBPath:       *dbPath,
		PublicURL:    *publicURL,
		Name:         *name,
		CookieSecure: *secureCookie,
	})
	if err != nil {
		log.Fatalf("initialize: %v", err)
	}
	defer srv.Close()

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on %s", *listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
}
