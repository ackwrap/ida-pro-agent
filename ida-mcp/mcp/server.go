package mcpserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"ida-mcp/ida"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maxRequestBodyBytes int64 = 1 << 20

// NewServer builds the fixed direct and domain tool catalog without change notifications.
func NewServer(version string, backend ida.Backend, options ...ServerOption) (*mcp.Server, error) {
	config := serverConfig{}
	for _, option := range options {
		option(&config)
	}
	cursors, err := newCursorCodec()
	if err != nil {
		return nil, fmt.Errorf("initialize MCP cursors: %w", err)
	}
	server := mcp.NewServer(
		&mcp.Implementation{Name: "ida-mcp", Version: version},
		&mcp.ServerOptions{
			Capabilities: &mcp.ServerCapabilities{
				Logging: &mcp.LoggingCapabilities{},
				Tools:   &mcp.ToolCapabilities{ListChanged: false},
			},
		},
	)
	if err := registerTools(server, backend, cursors, config); err != nil {
		return nil, fmt.Errorf("register MCP tools: %w", err)
	}
	return server, nil
}

// NewHTTPHandler exposes the same MCP server and tools over optional Streamable HTTP.
func NewHTTPHandler(version string, backend ida.Backend, options ...ServerOption) (http.Handler, error) {
	server, err := NewServer(version, backend, options...)
	if err != nil {
		return nil, err
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: false, JSONResponse: true},
	)
	mux := http.NewServeMux()
	mux.Handle("/mcp", limitRequestBody(mcpHandler, maxRequestBodyBytes))
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{"status": "ok", "version": version})
	})
	return noCache(requireLocalOrigin(mux)), nil
}

func limitRequestBody(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.ContentLength > limit {
			http.Error(response, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		request.Body = http.MaxBytesReader(response, request.Body, limit)
		next.ServeHTTP(response, request)
	})
}

func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(response, request)
	})
}

func requireLocalOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(response, request)
			return
		}
		parsed, err := url.Parse(origin)
		if err != nil || parsed.User != nil || parsed.Host == "" || !isLocalOrigin(parsed) {
			http.Error(response, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(response, request)
	})
}

func isLocalOrigin(origin *url.URL) bool {
	if origin.Scheme != "http" && origin.Scheme != "https" {
		return false
	}
	if strings.EqualFold(origin.Hostname(), "localhost") {
		return true
	}
	ip := net.ParseIP(origin.Hostname())
	return ip != nil && ip.IsLoopback()
}
