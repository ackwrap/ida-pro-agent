package webmanager

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxManagerRequestBytes int64 = 4 << 10

type Server struct {
	clients    *ClientManager
	listener   net.Listener
	httpServer *http.Server
	host       string
	url        string
	token      string
	done       chan error
	version    string
	cancel     context.CancelFunc
}

type statusResponse struct {
	Version     string         `json:"version"`
	GatewayPath string         `json:"gatewayPath"`
	Clients     []ClientStatus `json:"clients"`
}

func Start(version, gatewayPath string) (*Server, error) {
	clients, err := NewClientManager(gatewayPath)
	if err != nil {
		return nil, err
	}
	return startServer(version, clients)
}

func startServer(version string, clients *ClientManager) (*Server, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate Web manager token: %w", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for Web manager: %w", err)
	}
	server := &Server{
		clients: clients, listener: listener,
		host:  listener.Addr().String(),
		url:   "http://" + listener.Addr().String(),
		token: base64.RawURLEncoding.EncodeToString(tokenBytes),
		done:  make(chan error, 1), version: version,
	}
	requestContext, cancelRequests := context.WithCancel(context.Background())
	server.cancel = cancelRequests
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.serveIndex)
	mux.HandleFunc("/icon.svg", server.serveIcon)
	mux.HandleFunc("/favicon.ico", server.serveFavicon)
	mux.HandleFunc("/api/status", server.serveStatus)
	mux.HandleFunc("/api/clients/", server.serveClientAction)
	server.httpServer = &http.Server{
		Handler:           server.securityHeaders(mux),
		BaseContext:       func(net.Listener) context.Context { return requestContext },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	go func() {
		err := server.httpServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		server.done <- err
	}()
	return server, nil
}

func (server *Server) URL() string {
	return server.url
}

func (server *Server) Done() <-chan error {
	return server.done
}

func (server *Server) Shutdown(ctx context.Context) error {
	server.cancel()
	return server.httpServer.Shutdown(ctx)
}

func (server *Server) serveIndex(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	page, err := template.New("manager").Parse(indexHTML)
	if err != nil {
		http.Error(response, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-"+server.token+"'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(response, map[string]string{"Token": server.token, "Version": server.version})
}

func (server *Server) serveIcon(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	response.Header().Set("Content-Type", "image/svg+xml")
	_, _ = response.Write(iconSVG)
}

func (server *Server) serveFavicon(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	response.Header().Set("Content-Type", "image/x-icon")
	_, _ = response.Write(IconICO())
}

func (server *Server) serveStatus(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		methodNotAllowed(response, http.MethodGet)
		return
	}
	if !server.authorized(request, false) {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	writeJSON(response, http.StatusOK, statusResponse{
		Version: server.version, GatewayPath: server.clients.GatewayPath(), Clients: server.clients.Status(ctx),
	})
}

func (server *Server) serveClientAction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		methodNotAllowed(response, http.MethodPost)
		return
	}
	if !server.authorized(request, true) {
		http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxManagerRequestBytes)
	parts := strings.Split(strings.TrimPrefix(request.URL.Path, "/api/clients/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[0] == "" {
		http.NotFound(response, request)
		return
	}
	actionIndex := 1
	skills := false
	if len(parts) == 3 {
		if parts[1] != "skills" {
			http.NotFound(response, request)
			return
		}
		skills = true
		actionIndex = 2
	}
	enabled := false
	switch parts[actionIndex] {
	case "install":
		enabled = true
	case "remove":
	default:
		http.NotFound(response, request)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	var err error
	if skills {
		err = server.clients.SetSkillsEnabled(parts[0], enabled)
	} else {
		err = server.clients.SetEnabled(ctx, parts[0], enabled)
	}
	if err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"ok": true})
}

func (server *Server) authorized(request *http.Request, requireOrigin bool) bool {
	provided := request.Header.Get("X-IDA-AGENT-Token")
	if subtle.ConstantTimeCompare([]byte(provided), []byte(server.token)) != 1 {
		return false
	}
	origin := request.Header.Get("Origin")
	if origin == "" {
		return !requireOrigin
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Scheme == "http" && parsed.User == nil &&
		parsed.Host == server.host && origin == server.url
}

func (server *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		if request.Host != server.host {
			http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func methodNotAllowed(response http.ResponseWriter, allowed string) {
	response.Header().Set("Allow", allowed)
	http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
