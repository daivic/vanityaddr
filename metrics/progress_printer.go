package metrics

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
)

// ProgressPrinter displays live progress statistics for the vanity address search
type ProgressPrinter struct {
	attempts  *uint64
	start     time.Time
	prefixLen int
}

// NewProgressPrinter creates a new progress printer
func NewProgressPrinter(attempts *uint64, start time.Time, prefixLen int) *ProgressPrinter {
	return &ProgressPrinter{
		attempts:  attempts,
		start:     start,
		prefixLen: prefixLen,
	}
}

// Start begins printing progress updates every second until context is cancelled
func (p *ProgressPrinter) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	var m runtime.MemStats
	var lastUsage syscall.Rusage
	var lastTime time.Time
	
	// Initialize CPU tracking
	syscall.Getrusage(syscall.RUSAGE_SELF, &lastUsage)
	lastTime = time.Now()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total := atomic.LoadUint64(p.attempts)
			elapsed := time.Since(p.start)
			sec := elapsed.Seconds()
			if sec == 0 {
				sec = 1
			}
			rate := float64(total) / sec
			
			// Get runtime stats
			runtime.ReadMemStats(&m)
			allocMB := float64(m.Alloc) / 1024 / 1024
			
		// Get CPU percentage (normalized and raw)
		cpuNorm, cpuRaw := getCPUPercent(&lastUsage, &lastTime)
		coresUsed := cpuRaw / 100.0
		
		// Calculate remaining attempts and ETA
		expectedAttempts := math.Pow(16, float64(p.prefixLen)) / 2
		fullSearchSpace := math.Pow(16, float64(p.prefixLen))
		remainingExpected := int64(expectedAttempts - float64(total))
		remainingWorstCase := int64(fullSearchSpace - float64(total))
		
		expectedTime := calculateExpectedTime(p.prefixLen, rate, total)
		eta := formatDuration(expectedTime)
		
		// First line: attempts, rate, CPU, memory
		fmt.Printf("\r\033[K") // Clear line
		fmt.Printf("Attempts: %12d  |  Rate: %10.0f/s  |  CPU: %5.1f%% (%.1f/%d cores)  |  Mem: %5.1f MB\n",
			total, rate, cpuNorm, coresUsed, runtime.GOMAXPROCS(0), allocMB)
			
			// Second line: timing and remaining attempts
			fmt.Printf("\033[K") // Clear line
			fmt.Printf("Elapsed: %8s  |  ETA: %8s  |  Remaining (50%%/100%%): %12d / %12d\033[A",
				formatDuration(elapsed), eta, max(0, remainingExpected), max(0, remainingWorstCase))
		}
	}
}

// getCPUPercent returns the CPU usage percentage of the current process
// normalized to available cores (0-100% where 100% = all cores fully utilized)
func getCPUPercent(lastUsage *syscall.Rusage, lastTime *time.Time) (normalized float64, raw float64) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, 0
	}
	
	if lastUsage == nil {
		return 0, 0
	}
	
	// Calculate CPU time delta (user + system time)
	userDelta := float64(usage.Utime.Sec-lastUsage.Utime.Sec) + float64(usage.Utime.Usec-lastUsage.Utime.Usec)/1e6
	sysDelta := float64(usage.Stime.Sec-lastUsage.Stime.Sec) + float64(usage.Stime.Usec-lastUsage.Stime.Usec)/1e6
	cpuTime := userDelta + sysDelta
	
	// Calculate wall clock delta
	wallTime := time.Since(*lastTime).Seconds()
	
	// Raw CPU percentage = (cpu_time / wall_time) * 100
	// This can exceed 100% on multi-core systems
	rawPercent := (cpuTime / wallTime) * 100
	
	// Normalized percentage based on available cores (GOMAXPROCS)
	maxCores := float64(runtime.GOMAXPROCS(0))
	normalizedPercent := (rawPercent / maxCores)
	
	*lastUsage = usage
	*lastTime = time.Now()
	
	return normalizedPercent, rawPercent
}

// calculateExpectedTime estimates remaining time to find a match based on probability
// For a prefix of length N hex chars, probability = 1 / (16^N)
// Expected attempts = 16^N (on average, 16^N / 2 for 50% probability)
func calculateExpectedTime(prefixLen int, currentRate float64, currentAttempts uint64) time.Duration {
	if currentRate == 0 {
		return 0
	}
	
	// Expected attempts = 16^N / 2 (on average, halfway through search space)
	expectedAttempts := math.Pow(16, float64(prefixLen)) / 2
	remainingAttempts := expectedAttempts - float64(currentAttempts)
	
	// If we're past the expected halfway point, still show some estimate
	if remainingAttempts <= 0 {
		// Use the full search space as a pessimistic upper bound
		remainingAttempts = math.Pow(16, float64(prefixLen)) - float64(currentAttempts)
		if remainingAttempts <= 0 {
			return 0 // We've exceeded even the full search space
		}
	}
	
	// Time = remaining attempts / rate
	seconds := remainingAttempts / currentRate
	
	// Cap at reasonable maximum to avoid overflow
	if seconds > 365*24*3600 || math.IsInf(seconds, 0) {
		return 0 // Return 0 to indicate "effectively infinite"
	}
	
	return time.Duration(seconds * float64(time.Second))
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d == 0 {
		return "∞ (impractical)"
	}
	
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	days := d.Hours() / 24
	if days < 365 {
		return fmt.Sprintf("%.1fd", days)
	}
	years := days / 365
	return fmt.Sprintf("%.1fy", years)
}

