package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"ida-mcp/webmanager"
)

func main() {
	output := flag.String("output", "", "output .ico path")
	flag.Parse()
	if *output == "" {
		log.Fatal("-output is required")
	}
	path, err := filepath.Abs(*output)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, webmanager.IconICO(), 0o644); err != nil {
		log.Fatal(err)
	}
}
