package guard

import (
	"log"
	"os"
	"sync"
	"time"

	"aegis-shield/internal/netctl"
)

type Guard struct {
	execPath   string
	netCtl     *netctl.Controller
	stopChan   chan struct{}
	wg         sync.WaitGroup
	onUSBPanic func()
}

func NewGuard(controller *netctl.Controller, onUSBPanic func()) *Guard {
	execPath, err := os.Executable()
	if err != nil {
		execPath = os.Args[0]
	}

	return &Guard{
		execPath:   execPath,
		netCtl:     controller,
		stopChan:   make(chan struct{}),
		onUSBPanic: onUSBPanic,
	}
}

// Start begins the 3-second heartbeat monitor loop.
func (g *Guard) Start() {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-g.stopChan:
				return
			case <-ticker.C:
				if !g.isExecutableAccessible() {
					log.Printf("[Guard] CRITICAL ALERT: USB drive or binary %s disconnected or inaccessible!", g.execPath)
					// Immediately trigger DNS restoration
					g.netCtl.Restore()

					if g.onUSBPanic != nil {
						g.onUSBPanic()
					}
					os.Exit(1)
				}
			}
		}
	}()
	log.Printf("[Guard] Heartbeat active: Monitoring USB presence every 3 seconds.")
}

func (g *Guard) isExecutableAccessible() bool {
	info, err := os.Stat(g.execPath)
	if err != nil {
		return false
	}
	return info.Size() > 0
}

func (g *Guard) Stop() {
	close(g.stopChan)
	g.wg.Wait()
	log.Printf("[Guard] Heartbeat stopped cleanly.")
}
