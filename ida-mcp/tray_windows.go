//go:build windows

package main

import (
	"context"
	"log"

	"ida-mcp/webmanager"

	"github.com/getlantern/systray"
)

func runSystemTray(ctx context.Context, stop context.CancelFunc, managerURL string) error {
	go func() {
		<-ctx.Done()
		systray.Quit()
	}()
	systray.Run(func() {
		systray.SetIcon(webmanager.IconICO())
		systray.SetTitle("ida-mcp")
		systray.SetTooltip("ida-mcp local configuration manager")
		openItem := systray.AddMenuItem("Open IDA MCP Manager", "Configure MCP client connections")
		systray.AddSeparator()
		quitItem := systray.AddMenuItem("Exit ida-mcp", "Stop the local configuration manager")
		go func() {
			for {
				select {
				case <-openItem.ClickedCh:
					if err := openBrowser(managerURL); err != nil {
						log.Printf("open Web manager: %v", err)
					}
				case <-quitItem.ClickedCh:
					stop()
					systray.Quit()
					return
				case <-ctx.Done():
					return
				}
			}
		}()
		if err := openBrowser(managerURL); err != nil {
			log.Printf("open Web manager: %v", err)
		}
	}, stop)
	return nil
}
