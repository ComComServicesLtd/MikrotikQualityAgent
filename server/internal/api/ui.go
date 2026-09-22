package api

import (
	"embed"
	"net/http"
	"strings"
)

// The dashboard is embedded so the controller ships as one binary with no
// static-file deployment, no CDN and no build step. The same file also works
// opened directly from disk against a remote controller, which is what the
// CORS handling below exists for.
//
//go:embed ui/index.html
var uiFS embed.FS

func (s *Server) uiRoutes(mux *http.ServeMux) {
	page, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		// Only reachable if the embed directive and the file disagree, which
		// is a build-time mistake rather than a runtime condition.
		s.log.Error("dashboard asset missing from the binary", "error", err)
		return
	}

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// The mux treats "/" as a catch-all, so anything unmatched lands here.
		// Serving the dashboard for a mistyped API path would turn a 404 into
		// a confusing page of HTML.
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			problem(w, http.StatusNotFound, "not found", r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Everything is inline and self-contained, so the page needs no
		// external origins at all. Saying so explicitly means a future edit
		// that reaches for a CDN fails loudly rather than silently adding a
		// third-party dependency to an operations tool.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "+
				"img-src 'self' data:; connect-src *; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(page)
	})
}

// cors allows the dashboard to run from a file:// page or a different origin.
//
// A wildcard origin is safe here specifically because every authenticated
// endpoint takes a bearer token and none uses cookies: there is no ambient
// credential for another site to ride on. Credentials are deliberately not
// allowed, which also means the wildcard stays legal.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			// A PATCH or DELETE carrying Authorization is not a simple
			// request, so the browser preflights it.
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			allow := r.Header.Get("Access-Control-Request-Headers")
			if allow == "" {
				allow = "Authorization, Content-Type"
			}
			w.Header().Set("Access-Control-Allow-Headers", allow)
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// uiEnabled reports whether the dashboard should be served. Operators who
// front the controller with their own UI can turn it off.
func UIEnabled(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
