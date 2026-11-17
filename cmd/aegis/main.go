package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"aegis-shield/internal/coredns"
	"aegis-shield/internal/dashboard"
	"aegis-shield/internal/guard"
	"aegis-shield/internal/lists"
	"aegis-shield/internal/netctl"
	"aegis-shield/internal/stats"
	"aegis-shield/internal/tray"

	"golang.org/x/sys/windows"
)

const (
	Version   = "1.0"
	BuildDate = "2026-11-17"
	Owner     = "Pongsakorn"
)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

func attachConsoleIfPresent() {
	_, _, _ = procAttachConsole.Call(uintptr(^uint32(0)))
}

func main() {
	// If launched from an existing terminal, attach console output so logs are visible
	attachConsoleIfPresent()

	rescueOnly := flag.Bool("rescue", false, "Restore original DNS settings from previous session rescue file and exit")
	headless := flag.Bool("headless", false, "Run without system tray icon (console mode)")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("AEGIS Shield — Portable DNS Ad Blocker v%s (%s)\nOwner: %s | Tech Lead: (AI)\n", Version, BuildDate, Owner)
		os.Exit(0)
	}

	// 1. Rescue-only mode: Run if explicitly invoked with -rescue
	if *rescueOnly {
		log.Println("[Main] Running emergency DNS rescue mode...")
		if netctl.CheckAndRecoverPreviousSession() {
			log.Println("[Main] Rescue completed: All network interfaces restored to original DNS.")
		} else {
			log.Println("[Main] No uncleaned rescue session found.")
		}
		os.Exit(0)
	}

	// 2. Check Administrator elevation. Modifying DNS & binding port 53 requires admin rights.
	if !isElevated() {
		log.Println("[Main] Administrator rights required. Requesting UAC elevation...")
		if err := runAsAdmin(); err != nil {
			log.Fatalf("[Main] Failed to request UAC elevation: %v", err)
		}
		// Exit this non-elevated process; elevated instance will take over
		os.Exit(0)
	}

	log.Printf("==================================================")
	log.Printf("  AEGIS Shield v%s — Portable DNS Ad Blocker", Version)
	log.Printf("  Owner: %s | Date: %s", Owner, BuildDate)
	log.Printf("==================================================")

	// 3. Check for previous crash/abrupt shutdown rescue state
	if netctl.CheckAndRecoverPreviousSession() {
		log.Println("[Main] Recovered and restored DNS from prior session crash.")
	}

	// 4. Initialize Core Components
	listsMgr := lists.NewManager()
	statsCol := stats.NewCollector()
	dnsServer := coredns.NewServer(listsMgr, statsCol)
	netController := netctl.NewController()

	// 5. Ensure fail-safe panic recovery restores DNS unconditionally
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Main] CRITICAL PANIC DETECTED: %v", r)
			netController.Restore()
			statsCol.Flush()
		}
	}()

	// 6. Start DNS Server on 127.0.0.1:53 (UDP+TCP)
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("[Main] Fatal: Failed to start DNS server on 127.0.0.1:53: %v", err)
	}

	// 7. Activate NetCtl: Backup active interface DNS and point to 127.0.0.1
	if err := netController.Activate(); err != nil {
		dnsServer.Stop()
		log.Fatalf("[Main] Fatal: Failed to configure network interfaces: %v", err)
	}

	// 8. Start M3 Guard (3-second USB heartbeat and device disconnect monitor)
	usbGuard := guard.NewGuard(netController, func() {
		log.Println("[Guard] Emergency shutdown due to USB disconnection.")
		statsCol.Flush()
		dnsServer.Stop()
	})
	usbGuard.Start()

	// Channels for coordinated shutdown
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	quitOnce := sync.Once{}
	requestCleanShutdown := func() {
		quitOnce.Do(func() {
			log.Println("[Main] Initiating graceful shutdown...")
			usbGuard.Stop()
			netController.Restore()
			statsCol.Flush()
			dnsServer.Stop()
			time.Sleep(200 * time.Millisecond)
			log.Println("[Main] AEGIS Shield exited cleanly.")
			os.Exit(0)
		})
	}

	// 9. Start M6 Dashboard on http://127.0.0.1:8899
	dashServer := dashboard.NewServer(dnsServer, listsMgr, statsCol, netController, requestCleanShutdown)
	if err := dashServer.Start(); err != nil {
		log.Printf("[Main] Warning: Could not start dashboard: %v", err)
	}

	// Handle OS shutdown signals in background
	go func() {
		sig := <-shutdownChan
		log.Printf("[Main] Received signal %v", sig)
		requestCleanShutdown()
	}()

	// 10. Run Tray or Headless
	if *headless {
		log.Println("[Main] Running in headless mode. Press Ctrl+C to quit.")
		select {}
	} else {
		log.Println("[Main] Starting system tray icon...")
		trayMgr := tray.NewTrayManager(dnsServer, netController, requestCleanShutdown)
		trayMgr.Run()
	}
}

// isElevated checks if current Windows process token has elevated (Admin) privileges.
func isElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	var elevation uint32
	var size uint32
	err = windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&size,
	)
	if err != nil {
		return false
	}
	return elevation != 0
}

// runAsAdmin launches the executable with elevated administrator privileges using ShellExecute (runas).
func runAsAdmin() error {
	exePath, err := os.Executable()
	if err != nil {
		exePath = os.Args[0]
	}

	verbPtr, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exePath)
	cwdPtr, _ := windows.UTF16PtrFromString(os.TempDir())

	var args string
	if len(os.Args) > 1 {
		args = strings.Join(os.Args[1:], " ")
	}
	argPtr, _ := windows.UTF16PtrFromString(args)

	var showCmd int32 = windows.SW_NORMAL

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
}
