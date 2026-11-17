package tray

import (
	_ "embed"
	"log"
	"os/exec"
	"time"

	"aegis-shield/internal/coredns"
	"aegis-shield/internal/netctl"

	"github.com/getlantern/systray"
)

//go:embed shield_green.ico
var iconGreen []byte

//go:embed shield_amber.ico
var iconAmber []byte

type TrayManager struct {
	dnsServer *coredns.Server
	netCtl    *netctl.Controller
	onQuit    func()
}

func NewTrayManager(dnsServer *coredns.Server, netCtl *netctl.Controller, onQuit func()) *TrayManager {
	return &TrayManager{
		dnsServer: dnsServer,
		netCtl:    netCtl,
		onQuit:    onQuit,
	}
}

func (tm *TrayManager) Run() {
	systray.Run(tm.onReady, tm.onExit)
}

func (tm *TrayManager) Quit() {
	systray.Quit()
}

func (tm *TrayManager) onReady() {
	systray.SetIcon(iconGreen)
	systray.SetTitle("AEGIS Shield")
	systray.SetTooltip("AEGIS Shield — Active")

	mHeader := systray.AddMenuItem("🛡️ AEGIS Shield: ACTIVE", "Status: Active")
	mHeader.Disable()

	systray.AddSeparator()

	mDash := systray.AddMenuItem("🌐 Open Dashboard", "Open Web Dashboard at http://127.0.0.1:8899")
	mPause := systray.AddMenuItem("⏸️ Pause Protection (5m)", "Temporarily pause blocking")
	mFlush := systray.AddMenuItem("🧹 Flush DNS Cache", "Clear Windows DNS resolver cache")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("🔌 Restore DNS & Quit", "Restore original DNS and exit")

	// Event handling loop
	go func() {
		// Auto update icon/tooltip if unpaused automatically
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-mDash.ClickedCh:
				openBrowser("http://127.0.0.1:8899")

			case <-mPause.ClickedCh:
				isPaused, _ := tm.dnsServer.IsPaused()
				if isPaused {
					tm.dnsServer.Resume()
					systray.SetIcon(iconGreen)
					systray.SetTooltip("AEGIS Shield — Active")
					mHeader.SetTitle("🛡️ AEGIS Shield: ACTIVE")
					mPause.SetTitle("⏸️ Pause Protection (5m)")
				} else {
					tm.dnsServer.Pause(5 * time.Minute)
					systray.SetIcon(iconAmber)
					systray.SetTooltip("AEGIS Shield — PAUSED (5 min)")
					mHeader.SetTitle("⚠️ AEGIS Shield: PAUSED")
					mPause.SetTitle("▶️ Resume Protection")
				}

			case <-mFlush.ClickedCh:
				netctl.FlushDNS()

			case <-mQuit.ClickedCh:
				log.Printf("[Tray] User selected Quit & Restore.")
				systray.Quit()
				return

			case <-ticker.C:
				isPaused, _ := tm.dnsServer.IsPaused()
				if !isPaused {
					systray.SetIcon(iconGreen)
					systray.SetTooltip("AEGIS Shield — Active")
					mHeader.SetTitle("🛡️ AEGIS Shield: ACTIVE")
					mPause.SetTitle("⏸️ Pause Protection (5m)")
				}
			}
		}
	}()
}

func (tm *TrayManager) onExit() {
	log.Printf("[Tray] Systray exiting...")
	if tm.onQuit != nil {
		tm.onQuit()
	}
}

func openBrowser(url string) {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	_ = cmd.Start()
}
