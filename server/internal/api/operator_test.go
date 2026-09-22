package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ComComServicesLtd/MikrotikQualityAgent/server/internal/store"
)

func TestGroupInputAppliesSensibleDefaults(t *testing.T) {
	g := store.GroupInput{Name: "west-wan"}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	// Ring, not full: full mesh grows quadratically and will saturate small
	// routers, so it must never be what you get by not choosing.
	if g.MeshPlan != "ring" {
		t.Errorf("default plan should be ring, got %q", g.MeshPlan)
	}
	if g.IntervalS != 300 || g.MeshFanout != 3 {
		t.Errorf("unexpected defaults: %+v", g)
	}
}

func TestGroupInputRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		in   store.GroupInput
	}{
		{"no name", store.GroupInput{}},
		{"whitespace name", store.GroupInput{Name: "   "}},
		{"unknown plan", store.GroupInput{Name: "g", MeshPlan: "spiral"}},
		// A cadence shorter than a probe run queues work faster than agents can
		// complete it, and the backlog looks like agent failure.
		{"cadence too short", store.GroupInput{Name: "g", IntervalS: 5}},
	}
	for _, c := range cases {
		in := c.in
		if err := in.Validate(); err == nil {
			t.Errorf("%s: expected rejection", c.name)
		}
	}
}

func TestAutoBucketKeepsChartsToASaneNumberOfPoints(t *testing.T) {
	for _, c := range []struct {
		window time.Duration
		want   string
	}{
		{30 * time.Minute, "1m"},
		{6 * time.Hour, "5m"},
		{24 * time.Hour, "15m"},
		{7 * 24 * time.Hour, "1h"},
		{30 * 24 * time.Hour, "6h"},
		{89 * 24 * time.Hour, "1d"},
	} {
		got := autoBucket(c.window)
		if got != c.want {
			t.Errorf("window %v: want %s, got %s", c.window, c.want, got)
		}
		d := allowedBuckets[got]
		n := c.window / d
		if n < 20 || n > 2000 {
			t.Errorf("window %v with bucket %s gives %d points", c.window, got, n)
		}
	}
}

func TestTimeWindowDefaultsToTheLastHour(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/series", nil)
	w := httptest.NewRecorder()
	from, to, ok := timeWindow(w, r)
	if !ok {
		t.Fatal("should succeed with no parameters")
	}
	if d := to.Sub(from); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("default window should be an hour, got %v", d)
	}
}

func TestTimeWindowAcceptsARelativeWindow(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/v1/series?window=6h", nil)
	from, to, ok := timeWindow(httptest.NewRecorder(), r)
	if !ok {
		t.Fatal("should accept a duration")
	}
	if d := to.Sub(from); d < 5*time.Hour+59*time.Minute || d > 6*time.Hour+time.Minute {
		t.Errorf("want 6h, got %v", d)
	}
}

func TestTimeWindowRefusesRangesThatWouldHurtTheDatabase(t *testing.T) {
	// One dashboard tab must not be able to scan the whole hypertable.
	for _, q := range []string{
		"?window=200d",
		"?from=2020-01-01T00:00:00Z&to=2026-01-01T00:00:00Z",
		"?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", // inverted
		"?from=not-a-time",
		"?window=banana",
	} {
		w := httptest.NewRecorder()
		if _, _, ok := timeWindow(w, httptest.NewRequest("GET", "/api/v1/series"+q, nil)); ok {
			t.Errorf("%s should have been rejected", q)
		}
		if w.Code != 400 {
			t.Errorf("%s: want 400, got %d", q, w.Code)
		}
	}
}

func TestGroupInputDecodesSnakeCaseJSON(t *testing.T) {
	// Without explicit json tags this silently decodes to zero values and the
	// defaults win, so the API returns 200 with settings nobody asked for.
	var g store.GroupInput
	body := `{"name":"west-wan","description":"lab","mesh_plan":"full","mesh_fanout":5,"interval_s":20}`
	if err := json.Unmarshal([]byte(body), &g); err != nil {
		t.Fatal(err)
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	if g.MeshPlan != "full" || g.MeshFanout != 5 || g.IntervalS != 20 {
		t.Fatalf("request body was not honoured: %+v", g)
	}
}
