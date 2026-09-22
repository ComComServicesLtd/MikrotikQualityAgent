// Command controller is the central REST service: agent inventory, mesh
// scheduling, and result storage.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/api"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/scheduler"
	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/store"
)

// Embedded so the binary carries its own schema — no separate migration image
// to keep in step with the deployment.
//
//go:embed schema.sql
var schema string

func main() {
	// The distroless image has no shell and no curl, so the container
	// healthcheck re-executes this binary instead of shelling out.
	healthcheck := flag.Bool("healthcheck", false, "probe the local /readyz endpoint and exit")
	flag.Parse()

	if *healthcheck {
		os.Exit(probeSelf())
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(os.Getenv("MQ_LOG")),
	}))

	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// probeSelf returns a process exit code, so Docker reads it directly.
func probeSelf() int {
	addr := envOr("MQ_LISTEN_ADDR", ":8080")
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/readyz")
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run(log *slog.Logger) error {
	dsn := os.Getenv("MQ_DATABASE_URL")
	if dsn == "" {
		return errors.New("MQ_DATABASE_URL is required")
	}
	addr := envOr("MQ_LISTEN_ADDR", ":8080")
	operatorToken := os.Getenv("MQ_OPERATOR_TOKEN")
	if operatorToken == "" {
		log.Warn("MQ_OPERATOR_TOKEN not set — management endpoints and the dashboard are disabled")
	}
	serveUI := api.UIEnabled(envOr("MQ_SERVE_UI", "true"))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TimescaleDB may still be starting when the controller comes up under
	// compose, so retry rather than crash-looping the container.
	st, err := connectWithRetry(ctx, log, dsn, 30*time.Second)
	if err != nil {
		return err
	}
	defer st.Close()

	log.Info("applying schema")
	if err := st.Migrate(ctx, schema); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(st, log, operatorToken, serveUI).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go sweepLeases(ctx, log, st)
	go runScheduler(ctx, log, st)

	errCh := make(chan error, 1)
	go func() {
		log.Info("controller listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutdown requested")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func connectWithRetry(ctx context.Context, log *slog.Logger, dsn string, limit time.Duration) (*store.Store, error) {
	deadline := time.Now().Add(limit)
	for {
		st, err := store.New(ctx, dsn)
		if err == nil {
			return st, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		log.Info("database not ready, retrying", "error", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// sweepLeases returns work to the pending pool when an agent takes a task and
// never reports. Without it, a container that dies mid-task strands that
// measurement permanently.
func sweepLeases(ctx context.Context, log *slog.Logger, st *store.Store) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := st.ExpireLeases(ctx)
			if err != nil {
				log.Error("lease sweep failed", "error", err)
				continue
			}
			if n > 0 {
				log.Info("returned expired leases to the queue", "count", n)
			}
		}
	}
}

// runScheduler plans each group's mesh on its interval and writes the tasks.
//
// One cycle counter per group advances independently, which is what lets the
// partial plan rotate coverage without every group moving in lockstep.
func runScheduler(ctx context.Context, log *slog.Logger, st *store.Store) {
	cycles := map[string]int{}
	nextRun := map[string]time.Time{}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		groups, err := st.Groups(ctx)
		if err != nil {
			log.Error("scheduler could not list groups", "error", err)
			continue
		}

		for _, g := range groups {
			if t, ok := nextRun[g.Name]; ok && time.Now().Before(t) {
				continue
			}
			interval := time.Duration(g.IntervalS) * time.Second
			nextRun[g.Name] = time.Now().Add(interval)

			candidates, err := st.Candidates(ctx, g.Name)
			if err != nil {
				log.Error("scheduler could not load agents", "group", g.Name, "error", err)
				continue
			}

			cycle := cycles[g.Name]
			cycles[g.Name] = cycle + 1

			pairs, excluded := scheduler.PlanMesh(g.MeshPlan, g.MeshFanout, candidates, cycle)

			// Report what was left out. A mesh that quietly covers less than it
			// appears to is worse than one that declares its own gaps: an
			// operator looking at a sparse graph needs to know whether the
			// network is broken or the path was simply never tested.
			for _, e := range excluded {
				log.Info("scheduler excluded a pairing",
					"group", g.Name, "sender", e.Sender, "reflector", e.Reflector,
					"reason", e.Reason)
			}
			if len(pairs) == 0 {
				continue
			}

			n, err := st.CreateMeshTasks(ctx, g.Name, pairs, cycle, interval, defaultProbeParams())
			if err != nil {
				log.Error("scheduler could not create tasks", "group", g.Name, "error", err)
				continue
			}
			log.Info("scheduled a mesh cycle",
				"group", g.Name, "plan", g.MeshPlan, "cycle", cycle,
				"pairs", len(pairs), "tasks_created", n, "excluded", len(excluded))
		}

		if n, err := st.PurgeCompletedTasks(ctx, 24*time.Hour); err == nil && n > 0 {
			log.Debug("purged completed tasks", "count", n)
		}
	}
}

// defaultProbeParams is one 20 ms-spaced run of 300 packets at EF, which is
// about six seconds of traffic shaped like a voice call -- the thing users
// notice first when a path degrades.
func defaultProbeParams() map[string]any {
	return map[string]any{
		"count":         300,
		"interval_ms":   20,
		"payload_bytes": 172,
		"dscp":          46,
		"timeout_ms":    1000,
		"codec":         "g711",
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		if n, err := strconv.Atoi(s); err == nil {
			return slog.Level(n)
		}
		return slog.LevelInfo
	}
}
