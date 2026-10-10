package webmanager

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type updateFixture struct {
	Versions []struct {
		Installed, Tag string
		Newer          bool
	} `json:"versions"`
	InvalidVersions []string        `json:"invalidVersions"`
	Release         map[string]any  `json:"release"`
	Settings        json.RawMessage `json:"settings"`
	Cache           json.RawMessage `json:"cache"`
}

func loadUpdateFixture(t *testing.T) updateFixture {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "release", "testdata", "update-checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture updateFixture
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestUpdateSharedVersionAndReleaseFixtures(t *testing.T) {
	fixture := loadUpdateFixture(t)
	for _, test := range fixture.Versions {
		if got := hasNewerRelease(test.Installed, test.Tag); got != test.Newer {
			t.Errorf("%s -> %s: newer=%v", test.Installed, test.Tag, got)
		}
	}
	for _, version := range fixture.InvalidVersions {
		if _, ok := parseProductVersion(version); ok {
			t.Errorf("invalid version accepted: %q", version)
		}
	}
	now := time.Unix(1791590400, 0)
	body, _ := json.Marshal(fixture.Release)
	cache := decodeUpdateResponse(200, body, now, updateCache{})
	if cache.ReleaseTag != "v0.4.7" || cache.Error != "" {
		t.Fatalf("release: %+v", cache)
	}
	for _, test := range []struct {
		seconds     int64
		manual, due bool
	}{
		{0, false, false}, {86399, false, false}, {86400, false, true}, {59, true, false}, {60, true, true}, {-1, false, true},
	} {
		if got := updateCheckDue(cache, now.Add(time.Duration(test.seconds)*time.Second), test.manual); got != test.due {
			t.Errorf("cadence %+v: %v", test, got)
		}
	}
	for _, test := range []struct {
		field string
		value any
	}{
		{"draft", true}, {"prerelease", true}, {"draft", "false"}, {"prerelease", nil},
		{"html_url", "https://example.org/releases/tag/v0.4.7"}, {"tag_name", "v0.4.7-rc.1"}, {"published_at", ""},
	} {
		release := make(map[string]any)
		for key, value := range fixture.Release {
			release[key] = value
		}
		release[test.field] = test.value
		body, _ := json.Marshal(release)
		got := decodeUpdateResponse(200, body, now, cache)
		if got.Error == "" || got.ReleaseTag != cache.ReleaseTag {
			t.Errorf("unsafe metadata %+v: %+v", test, got)
		}
	}
	for _, status := range []int{0, 403, 404, 429, 500} {
		got := decodeUpdateResponse(status, nil, now, cache)
		if got.Error == "" || got.ReleaseTag != cache.ReleaseTag || updateCheckDue(got, now.Add(time.Second), false) {
			t.Errorf("failed check %d: %+v", status, got)
		}
	}
	if got := decodeUpdateResponse(200, []byte("not-json"), now, updateCache{}); got.Error == "" {
		t.Fatal("malformed release accepted")
	}
}

func TestUpdateStoreSharesOptOutAndCache(t *testing.T) {
	fixture := loadUpdateFixture(t)
	store := updateStore{t.TempDir()}
	if !store.automatic() {
		t.Fatal("missing config must default to enabled")
	}
	settingsPath := filepath.Join(store.directory, "update-settings.json")
	cachePath := filepath.Join(store.directory, "update-cache.json")
	if err := os.WriteFile(settingsPath, fixture.Settings, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, fixture.Cache, 0o600); err != nil {
		t.Fatal(err)
	}
	if store.automatic() || store.loadCache().ReleaseTag != "v0.4.7" {
		t.Fatal("shared fixtures rejected")
	}
	cache := store.loadCache()
	cache.CheckedAt++
	if err := store.save("update-cache.json", cache); err != nil {
		t.Fatal(err)
	}
	if store.automatic() {
		t.Fatal("background result overwrote opt-out")
	}
	if err := store.saveAutomatic(true); err != nil {
		t.Fatal(err)
	}
	if !store.automatic() {
		t.Fatal("opt-in did not persist")
	}
	for _, body := range []string{`{"version":1,"automatic":true,"unknown":0}`, `{"version":1}`, `null`, `{"version":2,"automatic":true}`, `{"version":1,"automatic":"true"}`, `{"version":1,"automatic":true} {}`} {
		if err := os.WriteFile(settingsPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if store.automatic() {
			t.Errorf("invalid settings enabled network access: %s", body)
		}
	}
	if err := os.WriteFile(cachePath, []byte(`{"version":1,"checkedAt":-1,"releaseTag":"v0.4.7","error":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if store.loadCache().CheckedAt != 0 {
		t.Fatal("invalid cache accepted")
	}
	if err := os.Remove(settingsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cachePath, settingsPath); err != nil {
		t.Skip("symlink privilege unavailable")
	}
	if store.automatic() {
		t.Fatal("symlink config accepted")
	}
	if err := store.saveAutomatic(true); err == nil {
		t.Fatal("symlink config overwritten")
	}
}

func waitForUpdate(t *testing.T, manager *updateManager) updateStatus {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		status := manager.status()
		if !status.Checking && status.CheckedAt != 0 {
			return status
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("update request did not complete")
	return updateStatus{}
}

func TestUpdateManagerOfflineOptOutManualAndDuplicateChecks(t *testing.T) {
	fixture := loadUpdateFixture(t)
	var calls atomic.Int32
	arrived := make(chan struct{}, 1)
	finish := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("User-Agent") != "ida-agent/0.4.6" || r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("Authorization") != "" || r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Error("incorrect public request headers")
		}
		arrived <- struct{}{}
		select {
		case <-finish:
		case <-r.Context().Done():
			return
		}
		json.NewEncoder(w).Encode(fixture.Release)
	}))
	defer upstream.Close()
	manager := newUpdateManager("0.4.6", t.TempDir())
	manager.endpoint = upstream.URL
	if err := manager.store.saveAutomatic(false); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager.start(ctx)
	manager.tick()
	if manager.status().Checking || calls.Load() != 0 {
		t.Fatal("opt-out triggered a network request")
	}
	var group sync.WaitGroup
	for range 20 {
		group.Go(manager.checkNow)
	}
	group.Wait()
	select {
	case <-arrived:
	case <-time.After(time.Second):
		t.Fatal("manual check did not start")
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent requests were not deduplicated")
	}
	close(finish)
	status := waitForUpdate(t, manager)
	if !status.Available || status.Automatic || status.ReleaseURL != releasePagePrefix+"v0.4.7" {
		t.Fatalf("manual result: %+v", status)
	}
	manager.checkNow()
	if calls.Load() != 1 || manager.status().Checking {
		t.Fatal("manual cooldown did not prevent duplicate check")
	}
	other := newUpdateManager("0.4.6", manager.store.directory)
	if other.status().Automatic || !other.status().Available {
		t.Fatal("second application did not share persisted cache and opt-out")
	}
	if err := manager.setAutomatic(true); err != nil {
		t.Fatal(err)
	}
	manager.tick()
	if calls.Load() != 1 || !other.status().Automatic {
		t.Fatal("fresh cache ignored or opt-in not shared")
	}
}

func TestUpdateManagerCancelsOnShutdownAndOptOut(t *testing.T) {
	for _, reason := range []string{"shutdown", "opt-out"} {
		t.Run(reason, func(t *testing.T) {
			arrived, cancelled := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(arrived); <-r.Context().Done(); close(cancelled) }))
			defer upstream.Close()
			manager := newUpdateManager("0.4.6", t.TempDir())
			manager.endpoint = upstream.URL
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			manager.start(ctx)
			select {
			case <-arrived:
			case <-time.After(time.Second):
				t.Fatal("automatic request did not start")
			}
			if reason == "shutdown" {
				cancel()
			} else if err := manager.setAutomatic(false); err != nil {
				t.Fatal(err)
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("request was not promptly cancelled")
			}
			if manager.store.loadCache().CheckedAt != 0 {
				t.Fatal("cancelled request cached as a completed check")
			}
		})
	}
}

func TestUpdateManagerBoundsResponsesAndTimeouts(t *testing.T) {
	for _, kind := range []string{"large", "timeout", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "large":
					w.Write([]byte(strings.Repeat("x", (1<<20)+1)))
				case "timeout":
					<-r.Context().Done()
				case "redirect":
					http.Redirect(w, r, "https://example.org", http.StatusFound)
				}
			}))
			defer upstream.Close()
			manager := newUpdateManager("0.4.6", t.TempDir())
			manager.endpoint = upstream.URL
			manager.client.Timeout = 50 * time.Millisecond
			manager.checkNow()
			status := waitForUpdate(t, manager)
			if status.Available || status.ReleaseURL != "" || !strings.Contains(status.Message, "Unable to check") {
				t.Fatalf("%s not rejected: %+v", kind, status)
			}
		})
	}
}

func TestUpdateAPIAuthorizationAndActions(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	if err := os.WriteFile(gateway, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	clients := newClientManager(gateway, home, func(string) (string, error) { return "", errors.New("not installed") }, nil)
	updates := newUpdateManager("0.4.6", filepath.Join(home, "updates"))
	if err := updates.store.saveAutomatic(false); err != nil {
		t.Fatal(err)
	}
	fixture := loadUpdateFixture(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(fixture.Release) }))
	defer upstream.Close()
	updates.endpoint = upstream.URL
	server, err := startServer("0.4.6", clients, updates)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	for _, test := range []struct {
		method, token, origin, body string
		status                      int
	}{
		{"GET", "", "", "", 403},
		{"POST", server.token, "", `{"action":"check"}`, 403},
		{"POST", server.token, "https://example.org", `{"action":"check"}`, 403},
		{"POST", server.token, server.URL(), `{"action":"configure"}`, 400},
		{"POST", server.token, server.URL(), `{"action":"check","endpoint":"https://example.org"}`, 400},
		{"POST", server.token, server.URL(), `{"action":"check"} {}`, 400},
		{"POST", server.token, server.URL(), `{"action":"configure","automatic":false}`, 200},
		{"GET", server.token, "", "", 200},
		{"POST", server.token, server.URL(), `{"action":"check"}`, 200},
	} {
		request, _ := http.NewRequest(test.method, server.URL()+"/api/updates", strings.NewReader(test.body))
		request.Header.Set("X-IDA-AGENT-Token", test.token)
		request.Header.Set("Origin", test.origin)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.status {
			t.Errorf("%s %s = %d, want %d", test.method, test.body, response.StatusCode, test.status)
		}
	}
	if !waitForUpdate(t, updates).Available {
		t.Fatal("authorized manual check did not complete")
	}
}
