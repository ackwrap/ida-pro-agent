package webmanager

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

type updateStatus struct {
	Automatic      bool   `json:"automatic"`
	Checking       bool   `json:"checking"`
	Available      bool   `json:"available"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	ReleaseURL     string `json:"releaseURL"`
	CheckedAt      int64  `json:"checkedAt"`
	Message        string `json:"message"`
}

type updateManager struct {
	mutex            sync.Mutex
	store            updateStore
	installed        string
	cache            updateCache
	checking, manual bool
	generation       uint64
	note             string
	ctx              context.Context
	cancel           context.CancelFunc
	client           *http.Client
	endpoint         string
}

func newUpdateManager(installed, directory string) *updateManager {
	store := updateStore{directory}
	return &updateManager{
		store: store, installed: installed, cache: store.loadCache(),
		ctx: context.Background(), endpoint: latestReleaseAPI,
		client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
}

func (manager *updateManager) start(ctx context.Context) {
	manager.ctx = ctx // Set before the server accepts requests.
	go func() {
		manager.tick()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				manager.mutex.Lock()
				manager.cancelRequestLocked()
				manager.mutex.Unlock()
				return
			case <-ticker.C:
				manager.tick()
			}
		}
	}()
}

func (manager *updateManager) cancelRequestLocked() {
	if manager.cancel != nil {
		manager.cancel()
	}
	manager.generation++
	manager.cancel = nil
	manager.checking = false
}

func (manager *updateManager) refreshCacheLocked() {
	shared := manager.store.loadCache()
	if shared.CheckedAt > manager.cache.CheckedAt && shared.CheckedAt <= time.Now().Unix() {
		manager.cache = shared
	}
}

func (manager *updateManager) tick() {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.refreshCacheLocked()
	if manager.store.automatic() {
		manager.checkLocked(false)
	} else if manager.checking && !manager.manual {
		manager.cancelRequestLocked()
	}
}

func (manager *updateManager) checkNow() {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.refreshCacheLocked()
	manager.checkLocked(true)
}

func (manager *updateManager) checkLocked(manual bool) {
	if manager.checking || manager.ctx.Err() != nil {
		return
	}
	if !updateCheckDue(manager.cache, time.Now(), manual) {
		if manual {
			manager.note = " Please wait one minute between manual checks."
		}
		return
	}
	manager.note = ""
	manager.checking, manager.manual = true, manual
	manager.generation++
	generation := manager.generation
	ctx, cancel := context.WithTimeout(manager.ctx, 15*time.Second)
	manager.cancel = cancel
	go func() {
		defer cancel()
		status := 0
		var body []byte
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, manager.endpoint, nil)
		if err == nil {
			request.Header.Set("User-Agent", "ida-agent/"+manager.installed)
			request.Header.Set("Accept", "application/vnd.github+json")
			request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
			response, fetchErr := manager.client.Do(request)
			if fetchErr == nil {
				body, err = io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
				response.Body.Close()
				if err == nil && len(body) <= 1<<20 {
					status = response.StatusCode
				}
			}
		}
		manager.mutex.Lock()
		defer manager.mutex.Unlock()
		if generation != manager.generation || manager.ctx.Err() != nil {
			return
		}
		manager.checking, manager.cancel = false, nil
		manager.cache = decodeUpdateResponse(status, body, time.Now(), manager.cache)
		_ = manager.store.save("update-cache.json", manager.cache)
	}()
}

func (manager *updateManager) setAutomatic(automatic bool) error {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	if err := manager.store.saveAutomatic(automatic); err != nil {
		return err
	}
	if !automatic && manager.checking && !manager.manual {
		manager.cancelRequestLocked()
	}
	if automatic {
		manager.refreshCacheLocked()
		manager.checkLocked(false)
	}
	return nil
}

func (manager *updateManager) status() updateStatus {
	manager.mutex.Lock()
	defer manager.mutex.Unlock()
	manager.refreshCacheLocked()
	url := ""
	if manager.cache.ReleaseTag != "" {
		url = releasePagePrefix + manager.cache.ReleaseTag
	}
	message := updateStatusText(manager.installed, manager.cache) + manager.note
	if manager.checking {
		message = "Checking GitHub... " + message
	}
	return updateStatus{manager.store.automatic(), manager.checking,
		hasNewerRelease(manager.installed, manager.cache.ReleaseTag), manager.installed,
		manager.cache.ReleaseTag, url, manager.cache.CheckedAt, message}
}

func (server *Server) serveUpdates(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !server.authorized(request, request.Method == http.MethodPost) {
		http.Error(response, "request forbidden", http.StatusForbidden)
		return
	}
	if server.updates == nil {
		http.Error(response, "updates unavailable", http.StatusServiceUnavailable)
		return
	}
	if request.Method == http.MethodPost {
		request.Body = http.MaxBytesReader(response, request.Body, maxManagerRequestBytes)
		var action struct {
			Action    string `json:"action"`
			Automatic *bool  `json:"automatic"`
		}
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&action) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(response, "invalid update action", http.StatusBadRequest)
			return
		}
		switch action.Action {
		case "check":
			if action.Automatic != nil {
				http.Error(response, "invalid update action", http.StatusBadRequest)
				return
			}
			server.updates.checkNow()
		case "configure":
			if action.Automatic == nil {
				http.Error(response, "automatic is required", http.StatusBadRequest)
				return
			}
			if err := server.updates.setAutomatic(*action.Automatic); err != nil {
				writeJSON(response, http.StatusInternalServerError, map[string]string{"error": "Unable to save update settings."})
				return
			}
		default:
			http.Error(response, "unsupported update action", http.StatusBadRequest)
			return
		}
	}
	writeJSON(response, http.StatusOK, server.updates.status())
}
