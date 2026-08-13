// Command vrmd serves the vendor risk assessment tool over HTTP.
//
// Kept thin by design (CLAUDE.md): flags, env, wiring. The pipeline is internal/assess and the
// rendering is internal/web.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aalcar/vrm/internal/assess"
	"github.com/aalcar/vrm/internal/config"
	"github.com/aalcar/vrm/internal/store"
	"github.com/aalcar/vrm/internal/web"
)

// shutdownGrace bounds how long a running assessment gets to finish after a signal. Generous
// on purpose: an assessment that has already paid for its API calls should be allowed to
// deliver them, and the analyst waiting on it has no way to tell a shutdown from a hang.
const shutdownGrace = 30 * time.Second

// readHeaderTimeout bounds the request line and headers only. It exists so a slow-loris
// connection cannot hold a goroutine forever, and it deliberately does not bound the body or
// the response — those are the assessment, which legitimately takes minutes.
const readHeaderTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "vrmd: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to config file")
	listen := flag.String("listen", "", "address to listen on (overrides config.listen)")
	flag.Parse()

	// Load .env if present. Absent in production by design, so a missing file is not an error,
	// and real environment variables always win over it.
	if err := config.LoadDotEnv(config.DotEnvFile); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	secrets, err := config.LoadSecrets()
	if err != nil {
		return err
	}

	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}
	if addr == "" {
		return errors.New("no listen address: set listen in config.yaml or pass --listen")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.New(ctx, secrets.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		return err
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// One Runner for the process, so every request shares one NVD and therefore one rate
	// limiter. Two limiters splitting NVD's five-requests-per-thirty-seconds budget would earn
	// a 403 that reads like a credential problem.
	runner := assess.NewRunner(cfg, secrets, st, assess.WithWarner(func(err error) {
		log.Warn("cache", "err", err)
	}))

	srv, err := web.New(runner, *configPath, web.WithLogger(log))
	if err != nil {
		return err
	}

	// WriteTimeout is deliberately absent. It bounds the time from the end of the request
	// headers to the end of the response, which for this server is the whole assessment —
	// timeouts.total, 360s by default. Any value that is not simply larger than that budget
	// truncates the most expensive reports in the tool, mid-HTML, with a 200 already sent.
	// The assessment carries its own deadline; this connection does not need a second one.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr, "config", *configPath)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down", "grace", shutdownGrace)
		// A fresh context: the one that was cancelled is what triggered this.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}
