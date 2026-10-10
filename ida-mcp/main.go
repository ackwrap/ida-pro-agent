package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	idabackend "ida-mcp/ida"
	"ida-mcp/ida/bridge"
	"ida-mcp/ida/discovery"
	mcpserver "ida-mcp/mcp"
	"ida-mcp/webmanager"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed VERSION
var versionFile string

var version = strings.TrimSpace(versionFile)

func main() {
	log.SetPrefix("[ida-mcp] ")
	transport := flag.String("transport", "stdio", "MCP transport: stdio or http")
	listenAddress := flag.String("listen", "127.0.0.1:8743", "loopback address for optional MCP HTTP")
	instanceDirectory := flag.String("instance-dir", "", "directory containing IDA Agent instance registry files")
	diagnostics := flag.Bool("diagnostics", false, "write MCP call metadata to stderr without arguments or results")
	webMode := flag.Bool("web", false, "run the loopback Web manager in the system tray")
	flag.Bool("grok", false, "deprecated compatibility flag; Grok behavior is now the default")
	removeSkillLinks := flag.Bool("remove-skill-links", false, "remove ida-mcp skill links managed by this installation")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *removeSkillLinks {
		executable, err := os.Executable()
		if err != nil {
			log.Fatalf("resolve Gateway executable: %v", err)
		}
		if err := webmanager.RemoveManagedSkillLinks(executable); err != nil {
			log.Fatalf("remove managed skill links: %v", err)
		}
		return
	}
	if *webMode {
		if *transport != "stdio" {
			log.Fatal("-web cannot be combined with -transport; configured clients launch stdio Gateway processes")
		}
		executable, err := os.Executable()
		if err != nil {
			log.Fatalf("resolve Gateway executable: %v", err)
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			log.Fatalf("resolve Gateway executable: %v", err)
		}
		if err := runWebMode(ctx, executable); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("serve Web manager: %v", err)
		}
		return
	}

	instances, err := configureDiscovery(*instanceDirectory)
	if err != nil {
		log.Fatalf("configure instance discovery: %v", err)
	}
	instances.ReportError = func(error) { log.Print("IDA instance probe failed") }
	bridgeClient := bridge.NewClient()
	bridgeClient.Timeout = 120 * time.Second
	backend := idabackend.NewBridgeBackend(instances, bridgeClient)

	var serverOptions []mcpserver.ServerOption
	if *diagnostics {
		serverOptions = append(serverOptions, mcpserver.WithDiagnostics(os.Stderr))
	}
	switch *transport {
	case "stdio":
		server, err := mcpserver.NewServer(version, backend, serverOptions...)
		if err != nil {
			log.Fatalf("configure MCP server: %v", err)
		}
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("serve MCP stdio: %v", err)
		}
	case "http":
		if err := serveHTTP(ctx, *listenAddress, backend, serverOptions...); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("unsupported transport %q; use stdio or http", *transport)
	}
}

func runWebMode(ctx context.Context, gatewayPath string) error {
	manager, err := webmanager.Start(version, gatewayPath)
	if err != nil {
		return err
	}
	trayContext, stopTray := context.WithCancel(ctx)
	defer stopTray()
	serverError := make(chan error, 1)
	go func() {
		if err := <-manager.Done(); err != nil {
			serverError <- err
		}
		stopTray()
	}()
	log.Printf("IDA MCP %s manager listening at %s", version, manager.URL())
	trayError := runSystemTray(trayContext, stopTray, manager.URL())
	stopTray()
	shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	shutdownError := manager.Shutdown(shutdownContext)
	select {
	case err := <-serverError:
		return err
	default:
	}
	if trayError != nil {
		return trayError
	}
	return shutdownError
}

func configureDiscovery(directory string) (*discovery.Discovery, error) {
	if directory != "" {
		return discovery.New(directory), nil
	}
	return discovery.NewDefault()
}

func serveHTTP(
	ctx context.Context, address string, backend idabackend.Backend, options ...mcpserver.ServerOption,
) error {
	if err := validateListenAddress(address); err != nil {
		return err
	}
	handler, err := mcpserver.NewHTTPHandler(version, backend, options...)
	if err != nil {
		return fmt.Errorf("configure MCP HTTP: %w", err)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}
	defer listener.Close()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 130 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(listener) }()
	log.Printf("IDA MCP %s listening at http://%s/mcp", version, listener.Addr())
	select {
	case err := <-serveError:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve MCP HTTP: %w", err)
		}
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown MCP HTTP: %w", err)
		}
	}
	return nil
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("invalid listen port %q: %w", port, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; remote HTTP requires authentication", address)
	}
	return nil
}
