package webmanager

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestManagerServerRequiresTokenAndSameOrigin(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	if err := os.WriteFile(gateway, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	writePackagedSkills(t, gateway)
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(home, "opencode"))
	manager := newClientManager(gateway, home, func(string) (string, error) {
		return "", errors.New("not installed")
	}, nil)
	server, err := startServer("test-version", manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	response, err := http.Get(server.URL() + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized status = %d", response.StatusCode)
	}

	request, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/status", nil)
	request.Header.Set("X-IDA-AGENT-Token", server.token)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var status statusResponse
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || status.Version != "test-version" || len(status.Clients) != len(managedClientIDs) {
		t.Fatalf("status response = %d %+v", response.StatusCode, status)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL()+"/api/clients/opencode/install", nil)
	request.Header.Set("X-IDA-AGENT-Token", server.token)
	request.Header.Set("Origin", "http://malicious.invalid")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin update status = %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodGet, server.URL(), nil)
	request.Host = "rebind.invalid"
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("rebinding Host status = %d", response.StatusCode)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL()+"/api/clients/opencode/install", nil)
	request.Header.Set("X-IDA-AGENT-Token", server.token)
	request.Header.Set("Origin", server.URL())
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("same-origin update status = %d: %s", response.StatusCode, body)
	}
	if current := manager.openCodeStatus(); !current.Current {
		t.Fatalf("OpenCode was not configured: %+v", current)
	}

	request, _ = http.NewRequest(http.MethodPost, server.URL()+"/api/clients/opencode/skills/install", nil)
	request.Header.Set("X-IDA-AGENT-Token", server.token)
	request.Header.Set("Origin", server.URL())
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !manager.skillStatus("opencode").Current {
		t.Fatalf("skill link update status = %d: %s", response.StatusCode, body)
	}

	for _, clientID := range []string{"antigravity", "claudecode", "zcode"} {
		for _, route := range []string{"install", "skills/install", "remove", "skills/remove"} {
			request, _ = http.NewRequest(http.MethodPost, server.URL()+"/api/clients/"+clientID+"/"+route, nil)
			request.Header.Set("X-IDA-AGENT-Token", server.token)
			request.Header.Set("Origin", server.URL())
			response, err = http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ = io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s %s status = %d: %s", clientID, route, response.StatusCode, body)
			}
			var clientStatus ClientStatus
			if clientID == "antigravity" {
				clientStatus = manager.antigravityStatus()
			} else if clientID == "claudecode" {
				clientStatus = manager.claudeCodeStatus()
			} else {
				clientStatus = manager.zcodeStatus()
			}
			skillStatus := manager.skillStatus(clientID)
			switch route {
			case "install":
				if !clientStatus.Current {
					t.Fatalf("%s install did not configure MCP: %+v", clientID, clientStatus)
				}
			case "skills/install":
				if !skillStatus.Current {
					t.Fatalf("%s skills install did not link skills: %+v", clientID, skillStatus)
				}
			case "remove":
				if clientStatus.Configured {
					t.Fatalf("%s remove left MCP configured: %+v", clientID, clientStatus)
				}
			case "skills/remove":
				if skillStatus.Configured {
					t.Fatalf("%s skills remove left links configured: %+v", clientID, skillStatus)
				}
			}
		}
	}
}

func TestManagerShutdownCancelsActiveClientCommand(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	if err := os.WriteFile(gateway, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(home, "codex.exe")
	if err := os.WriteFile(executable, []byte("test CLI"), 0o700); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var startedOnce sync.Once
	manager := newClientManager(gateway, home, func(string) (string, error) {
		return executable, nil
	}, func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	server, err := startServer("test-version", manager)
	if err != nil {
		t.Fatal(err)
	}
	requestDone := make(chan error, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodGet, server.URL()+"/api/status", nil)
		request.Header.Set("X-IDA-AGENT-Token", server.token)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("Codex status command did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-requestDone:
	case <-time.After(5 * time.Second):
		t.Fatal("active manager request was not canceled")
	}
}

func TestManagerPageUsesNonceAndLocalAssets(t *testing.T) {
	isolateClientEnvironment(t)
	home := t.TempDir()
	gateway := filepath.Join(home, "ida-mcp.exe")
	if err := os.WriteFile(gateway, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	manager := newClientManager(gateway, home, func(string) (string, error) {
		return "", errors.New("not installed")
	}, nil)
	server, err := startServer("0.2.0", manager)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer server.Shutdown(ctx)

	response, err := http.Get(server.URL())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "<h1>IDA MCP</h1>") ||
		!strings.Contains(string(body), `nonce="`+server.token+`"`) {
		t.Fatalf("manager page response is incomplete: %d", response.StatusCode)
	}
	policy := response.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "script-src 'nonce-"+server.token+"'") || strings.Contains(policy, "https:") {
		t.Fatalf("unexpected content security policy: %s", policy)
	}
	response, err = http.Get(server.URL() + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	favicon, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "image/x-icon" ||
		!bytes.Equal(favicon, IconICO()) {
		t.Fatal("Web favicon does not match the shared application icon")
	}
}

func TestGeneratedTrayIconIsICO(t *testing.T) {
	icon := IconICO()
	if len(icon) < 22 || binary.LittleEndian.Uint16(icon[2:4]) != 1 ||
		binary.LittleEndian.Uint16(icon[4:6]) != uint16(len(iconSizes)) {
		t.Fatalf("invalid ICO header: %x", icon[:min(len(icon), 22)])
	}
	for index, size := range iconSizes {
		entry := icon[6+index*16 : 6+(index+1)*16]
		if size < 256 && (entry[0] != byte(size) || entry[1] != byte(size)) {
			t.Fatalf("ICO entry %d dimensions = %dx%d", index, entry[0], entry[1])
		}
		offset := binary.LittleEndian.Uint32(entry[12:16])
		length := binary.LittleEndian.Uint32(entry[8:12])
		if int(offset+length) > len(icon) {
			t.Fatalf("ICO entry %d range = %d..%d, size %d", index, offset, offset+length, len(icon))
		}
	}
}
