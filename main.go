package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type App struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	WorkDir           string   `json:"workdir"`
	StartCmd          string   `json:"start_cmd"`
	StopCmd           string   `json:"stop_cmd"`
	StatusCmd         string   `json:"status_cmd"`
	ProcMatch         string   `json:"proc_match"`
	Deps              []string `json:"deps"`
	MetricsCmd        string   `json:"metrics_cmd"`
	WorkerPidCmd      string   `json:"worker_pid_cmd"`
	WorkerMin         int      `json:"worker_min"`
	WorkerMax         int      `json:"worker_max"`
	WorkerAddCmd      string   `json:"worker_add_cmd"`
	WorkerRemoveCmd   string   `json:"worker_remove_cmd"`
	WorkerCountCmd    string   `json:"worker_count_cmd"`
	LogPattern        string   `json:"log_pattern"`
	Port              string   `json:"port"`
	IsSecurityDashboard bool   `json:"is_security_dashboard"`
	// Auto-scaling configuration
	AutoScaleEnabled       bool    `json:"auto_scale_enabled"`        // enable auto-scaling on startup
	AutoScaleUpThreshold   float64 `json:"auto_scale_up_threshold"`   // req/min per worker to scale up (default: 8)
	AutoScaleDownThreshold float64 `json:"auto_scale_down_threshold"` // req/min per worker to scale down (default: 2)
	// Alert thresholds
	AlertWorkerMin int `json:"alert_worker_min"` // Alert if workers drop below this
	AlertWorkerMax int `json:"alert_worker_max"` // Alert if workers exceed this
}

// Auto-scaling state
type AutoScaleState struct {
	Enabled       bool
	LastAction    string    // "scale_up", "scale_down", "optimal", etc.
	LastActionAt  time.Time
	LastReqRate   float64
	TargetWorkers int
	// Enhanced metrics
	ReqPerWorker  float64   // current load per worker
	CooldownSecs  int       // seconds until next scale allowed
	LastScaleDesc string    // e.g., "↑ 2→3" or "↓ 4→3"
	BusyWorkers   int       // workers currently handling requests
	IdleWorkers   int       // workers waiting for requests
}

// Alert state tracking for workers
type AlertState struct {
	LastAlertTime   time.Time
	LastAlertType   string // "low", "high", "normal"
	LastWorkerCount int
}

// System resource alert state
type SystemAlertState struct {
	LastCPULevel    string    // "50", "70", "90", "normal"
	LastCPUAlertAt  time.Time
	LastRAMLevel    string    // "50", "70", "90", "normal"
	LastRAMAlertAt  time.Time
}

// App status tracking for crash detection
type AppStatusTracker struct {
	LastStatus    string    // "running" or "stopped"
	LastChangeAt  time.Time
}

type Config struct {
	Password     string `json:"password"`
	Port         int    `json:"port"`
	SlackWebhook string `json:"slack_webhook"`
	SlackEnabled bool   `json:"slack_enabled"`
	Apps         []App  `json:"apps"`
}

type SystemMetrics struct {
	CPUPercent  float64
	MemUsedGB   float64
	MemTotalGB  float64
	MemPercent  float64
	DiskUsedGB  float64
	DiskTotalGB float64
	DiskPercent float64
	Uptime      string
	LoadAvg     string
}

type AppMetric struct {
	Label string
	Value string
	Color string
}

type ErrorURL struct {
	Type      string
	URL       string
	Count     int
	LastTime  string
	TimeAgo   string
	Timestamp time.Time
}

type RecentTicket struct {
	URL       string
	Code      string
	Timestamp time.Time
	TimeAgo   string
	Device    string
	Browser   string
}

type TicketHit struct {
	Code      string
	Count     int
	LastTime  string
	LastAgo   string
	Devices   string // "iPhone, Mac" etc
}

type DayTicketLog struct {
	Label       string // "Today", "Yesterday", "2 Days Ago"
	Date        string // "02 Apr 2026"
	UniqueHits  int
	TotalHits   int
	Hits        []TicketHit
}

type EntryPoint struct {
	Name   string
	Status string
	Color  string
}

type OrphanProcess struct {
	PID    int
	Name   string
	Port   string
	User   string
	Memory string
	Uptime string
}

type SecurityData struct {
	SafetyScore     int
	ScoreColor      string
	BannedNow       int
	BannedTotal     int
	SSHFails24h     int
	Probes24h       int
	Blocked24h      int
	UniqueAttackers int
	LastAttack      string
	LastAttackAgo   string
	EntryPoints     []EntryPoint
	OrphanProcesses []OrphanProcess
}

type AppStatus struct {
	App          App
	Status       string
	CPUPercent   float64
	MemMB        float64
	DiskSize     string
	ProcCount    int
	Metrics      []AppMetric
	WorkerCount  int
	CanScale     bool
	ErrorURLs     []ErrorURL
	RecentTickets []RecentTicket
	DayLogs       []DayTicketLog
	RefreshTime  string
	Security     *SecurityData
	// Auto-scaling status
	AutoScale    *AutoScaleState
}

var (
	config     Config
	configFile = "/opt/server-control/config.json"
	mu         sync.Mutex
	prevIdle   uint64
	prevTotal  uint64
	errorURLCache     = make(map[string][]ErrorURL)
	errorURLCacheTime time.Time
	errorURLCacheMu   sync.RWMutex
	// Auto-scaling state per app
	autoScaleStates   = make(map[string]*AutoScaleState)
	autoScaleMu       sync.RWMutex
	// Alert state per app
	alertStates       = make(map[string]*AlertState)
	alertMu           sync.RWMutex
	// System resource alert state
	systemAlertState  = &SystemAlertState{}
	systemAlertMu     sync.Mutex
	// App status tracking for crash detection
	appStatusTrackers = make(map[string]*AppStatusTracker)
	appStatusMu       sync.RWMutex
)

// Alert cooldown duration (5 minutes)
const alertCooldown = 5 * time.Minute

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	dropInDir := filepath.Join(filepath.Dir(configFile), "apps.d")
	files, err := filepath.Glob(filepath.Join(dropInDir, "*.json"))
	if err != nil {
		return err
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("Warning: failed to read %s: %v", f, err)
			continue
		}
		var app App
		if err := json.Unmarshal(data, &app); err != nil {
			log.Printf("Warning: failed to parse %s: %v", f, err)
			continue
		}
		if app.Name != "" {
			config.Apps = append(config.Apps, app)
			log.Printf("Loaded app from %s: %s", filepath.Base(f), app.Name)
		}
	}
	return nil
}

func runCmdTimeout(cmd string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "bash", "-c", cmd)
	out, err := c.CombinedOutput()
	return string(out), err
}

// sendSlackAlert sends a notification to Slack
func sendSlackAlert(message string) error {
	if !config.SlackEnabled || config.SlackWebhook == "" {
		return nil
	}

	payload := map[string]string{"text": message}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", config.SlackWebhook, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	log.Printf("[Slack] Alert sent: %s", strings.ReplaceAll(message, "\n", " "))
	return nil
}

// checkWorkerAlerts checks worker counts and sends alerts if needed
func checkWorkerAlerts(app App, workerCount int) {
	// Only check apps with alert thresholds configured
	if app.AlertWorkerMin == 0 && app.AlertWorkerMax == 0 {
		return
	}

	alertMu.Lock()
	defer alertMu.Unlock()

	// Initialize state if needed
	if _, ok := alertStates[app.Name]; !ok {
		alertStates[app.Name] = &AlertState{}
	}
	state := alertStates[app.Name]

	// Get current time in IST for display
	ist := time.FixedZone("IST", 5*3600+30*60)
	timeStr := time.Now().In(ist).Format("15:04 IST")

	var alertType string
	var message string

	// Check conditions
	if app.AlertWorkerMin > 0 && workerCount < app.AlertWorkerMin {
		alertType = "low"
		message = fmt.Sprintf(":warning: *%s Alert*\nWorkers below minimum: %d/%d\nTime: %s",
			app.Name, workerCount, app.AlertWorkerMin, timeStr)
	} else if app.AlertWorkerMax > 0 && workerCount > app.AlertWorkerMax {
		alertType = "high"
		message = fmt.Sprintf(":chart_with_upwards_trend: *%s Alert*\nHigh traffic - Workers: %d/%d\nTime: %s",
			app.Name, workerCount, app.AlertWorkerMax, timeStr)
	} else if state.LastAlertType == "low" || state.LastAlertType == "high" {
		// Workers returned to normal
		alertType = "normal"
		message = fmt.Sprintf(":white_check_mark: *%s Normalized*\nWorkers: %d (was %d)\nTime: %s",
			app.Name, workerCount, state.LastWorkerCount, timeStr)
	} else {
		// All good, nothing to report
		return
	}

	// Check cooldown - don't re-alert same condition within cooldown period
	if alertType == state.LastAlertType && time.Since(state.LastAlertTime) < alertCooldown {
		return
	}

	// Send alert
	if err := sendSlackAlert(message); err != nil {
		log.Printf("[Alert] Failed to send Slack alert for %s: %v", app.Name, err)
	}

	// Update state
	state.LastAlertTime = time.Now()
	state.LastAlertType = alertType
	state.LastWorkerCount = workerCount
}

// checkSystemResourceAlerts checks CPU and RAM levels and sends alerts
func checkSystemResourceAlerts(sysMetrics SystemMetrics) {
	systemAlertMu.Lock()
	defer systemAlertMu.Unlock()

	ist := time.FixedZone("IST", 5*3600+30*60)
	timeStr := time.Now().In(ist).Format("15:04 IST")

	// Check CPU levels
	var cpuLevel string
	if sysMetrics.CPUPercent >= 95 {
		cpuLevel = "95"
	} else if sysMetrics.CPUPercent >= 85 {
		cpuLevel = "85"
	} else if sysMetrics.CPUPercent >= 75 {
		cpuLevel = "75"
	} else {
		cpuLevel = "normal"
	}

	// Send CPU alert if level changed or crossed a new threshold
	if cpuLevel != systemAlertState.LastCPULevel && cpuLevel != "normal" {
		// Only alert if we haven't alerted this level recently (5 min cooldown)
		if time.Since(systemAlertState.LastCPUAlertAt) >= alertCooldown || cpuLevel > systemAlertState.LastCPULevel {
			var emoji string
			switch cpuLevel {
			case "95":
				emoji = ":rotating_light:"
			case "85":
				emoji = ":warning:"
			case "75":
				emoji = ":eyes:"
			}
			message := fmt.Sprintf("%s *Server CPU Alert*\nCPU usage: %.0f%% (threshold: %s%%)\nLoad: %s\nTime: %s",
				emoji, sysMetrics.CPUPercent, cpuLevel, sysMetrics.LoadAvg, timeStr)
			if err := sendSlackAlert(message); err != nil {
				log.Printf("[Alert] Failed to send CPU alert: %v", err)
			}
			systemAlertState.LastCPUAlertAt = time.Now()
		}
	} else if cpuLevel == "normal" && systemAlertState.LastCPULevel != "normal" && systemAlertState.LastCPULevel != "" {
		// CPU returned to normal
		message := fmt.Sprintf(":white_check_mark: *Server CPU Normalized*\nCPU usage: %.0f%% (was >%s%%)\nTime: %s",
			sysMetrics.CPUPercent, systemAlertState.LastCPULevel, timeStr)
		if err := sendSlackAlert(message); err != nil {
			log.Printf("[Alert] Failed to send CPU recovery alert: %v", err)
		}
	}
	systemAlertState.LastCPULevel = cpuLevel

	// Check RAM levels
	var ramLevel string
	if sysMetrics.MemPercent >= 95 {
		ramLevel = "95"
	} else if sysMetrics.MemPercent >= 85 {
		ramLevel = "85"
	} else if sysMetrics.MemPercent >= 75 {
		ramLevel = "75"
	} else {
		ramLevel = "normal"
	}

	// Send RAM alert if level changed or crossed a new threshold
	if ramLevel != systemAlertState.LastRAMLevel && ramLevel != "normal" {
		// Only alert if we haven't alerted this level recently (5 min cooldown)
		if time.Since(systemAlertState.LastRAMAlertAt) >= alertCooldown || ramLevel > systemAlertState.LastRAMLevel {
			var emoji string
			switch ramLevel {
			case "95":
				emoji = ":rotating_light:"
			case "85":
				emoji = ":warning:"
			case "75":
				emoji = ":eyes:"
			}
			message := fmt.Sprintf("%s *Server RAM Alert*\nRAM usage: %.0f%% (%.1f/%.1f GB)\nThreshold: %s%%\nTime: %s",
				emoji, sysMetrics.MemPercent, sysMetrics.MemUsedGB, sysMetrics.MemTotalGB, ramLevel, timeStr)
			if err := sendSlackAlert(message); err != nil {
				log.Printf("[Alert] Failed to send RAM alert: %v", err)
			}
			systemAlertState.LastRAMAlertAt = time.Now()
		}
	} else if ramLevel == "normal" && systemAlertState.LastRAMLevel != "normal" && systemAlertState.LastRAMLevel != "" {
		// RAM returned to normal
		message := fmt.Sprintf(":white_check_mark: *Server RAM Normalized*\nRAM usage: %.0f%% (was >%s%%)\nTime: %s",
			sysMetrics.MemPercent, systemAlertState.LastRAMLevel, timeStr)
		if err := sendSlackAlert(message); err != nil {
			log.Printf("[Alert] Failed to send RAM recovery alert: %v", err)
		}
	}
	systemAlertState.LastRAMLevel = ramLevel
}

// checkAppCrash detects if a previously running app has crashed
func checkAppCrash(appName string, currentStatus string) {
	appStatusMu.Lock()
	defer appStatusMu.Unlock()

	// Initialize tracker if needed
	if _, ok := appStatusTrackers[appName]; !ok {
		appStatusTrackers[appName] = &AppStatusTracker{
			LastStatus:   currentStatus,
			LastChangeAt: time.Now(),
		}
		return
	}

	tracker := appStatusTrackers[appName]

	// Check if status changed from running to stopped (crash)
	if tracker.LastStatus == "running" && currentStatus == "stopped" {
		ist := time.FixedZone("IST", 5*3600+30*60)
		timeStr := time.Now().In(ist).Format("15:04 IST")

		message := fmt.Sprintf(":skull: *App Crashed*\n*%s* is now STOPPED\nWas running since: %s\nTime: %s",
			appName, tracker.LastChangeAt.In(ist).Format("15:04 IST"), timeStr)
		if err := sendSlackAlert(message); err != nil {
			log.Printf("[Alert] Failed to send crash alert for %s: %v", appName, err)
		}
	} else if tracker.LastStatus == "stopped" && currentStatus == "running" {
		// App recovered/started
		ist := time.FixedZone("IST", 5*3600+30*60)
		timeStr := time.Now().In(ist).Format("15:04 IST")

		message := fmt.Sprintf(":rocket: *App Started*\n*%s* is now RUNNING\nTime: %s",
			appName, timeStr)
		if err := sendSlackAlert(message); err != nil {
			log.Printf("[Alert] Failed to send start alert for %s: %v", appName, err)
		}
	}

	// Update tracker if status changed
	if tracker.LastStatus != currentStatus {
		tracker.LastStatus = currentStatus
		tracker.LastChangeAt = time.Now()
	}
}

func getSystemMetrics() SystemMetrics {
	m := SystemMetrics{}
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 0 {
			fields := strings.Fields(lines[0])
			if len(fields) >= 5 {
				var total, idle uint64
				for i := 1; i < len(fields); i++ {
					val, _ := strconv.ParseUint(fields[i], 10, 64)
					total += val
					if i == 4 { idle = val }
				}
				if prevTotal > 0 {
					totalDelta := float64(total - prevTotal)
					idleDelta := float64(idle - prevIdle)
					if totalDelta > 0 { m.CPUPercent = (1.0 - idleDelta/totalDelta) * 100 }
				}
				prevTotal = total
				prevIdle = idle
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal, memAvail uint64
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "MemTotal:") { fmt.Sscanf(line, "MemTotal: %d kB", &memTotal) }
			if strings.HasPrefix(line, "MemAvailable:") { fmt.Sscanf(line, "MemAvailable: %d kB", &memAvail) }
		}
		m.MemTotalGB = float64(memTotal) / 1024 / 1024
		m.MemUsedGB = float64(memTotal-memAvail) / 1024 / 1024
		if memTotal > 0 { m.MemPercent = float64(memTotal-memAvail) / float64(memTotal) * 100 }
	}
	out, _ := runCmdTimeout("df -B1 / | tail -1", 2*time.Second)
	fields := strings.Fields(out)
	if len(fields) >= 4 {
		total, _ := strconv.ParseUint(fields[1], 10, 64)
		used, _ := strconv.ParseUint(fields[2], 10, 64)
		m.DiskTotalGB = float64(total) / 1024 / 1024 / 1024
		m.DiskUsedGB = float64(used) / 1024 / 1024 / 1024
		if total > 0 { m.DiskPercent = float64(used) / float64(total) * 100 }
	}
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		var secs float64
		fmt.Sscanf(string(data), "%f", &secs)
		days := int(secs) / 86400
		hours := (int(secs) % 86400) / 3600
		mins := (int(secs) % 3600) / 60
		m.Uptime = fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 { m.LoadAvg = strings.Join(fields[:3], " ") }
	}
	return m
}

// Cached process stats — ONE ps aux call serves all apps
type procCacheEntry struct {
	Count int
	CPU   float64
	MemMB float64
}
var procCache map[string]procCacheEntry
var procCacheTime time.Time
var procCacheMu sync.Mutex

// Cached disk usage — refreshed every 5 minutes (du is expensive)
var diskCache map[string]string // workdir -> "1.2G", "78M", etc.
var diskCacheTime time.Time
var diskCacheMu sync.Mutex

func refreshDiskCache(apps []App) {
	diskCacheMu.Lock()
	defer diskCacheMu.Unlock()
	if time.Since(diskCacheTime) < 24*time.Hour { return }
	diskCache = make(map[string]string)
	// Build one du command for all workdirs
	var dirs []string
	for _, app := range apps {
		if app.WorkDir != "" {
			dirs = append(dirs, app.WorkDir)
		}
	}
	if len(dirs) == 0 { return }
	cmd := "du -sh " + strings.Join(dirs, " ") + " 2>/dev/null"
	out, err := runCmdTimeout(cmd, 30*time.Second)
	if err != nil { return }
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			diskCache[parts[1]] = parts[0]
		}
	}
	diskCacheTime = time.Now()
}

func refreshProcessCache(apps []App) {
	procCacheMu.Lock()
	defer procCacheMu.Unlock()
	if time.Since(procCacheTime) < 60*time.Second { return }
	procCache = make(map[string]procCacheEntry)

	// One ps aux call for ALL processes
	psOut, err := runCmdTimeout("ps aux --no-headers", 3*time.Second)
	if err != nil { return }

	// Get total memory for MB calculation
	var memTotalKB uint64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "MemTotal:") {
				fmt.Sscanf(scanner.Text(), "MemTotal: %d kB", &memTotalKB)
				break
			}
		}
	}

	psLines := strings.Split(strings.TrimSpace(psOut), "\n")

	// Build PID -> cpu/mem map from ps aux
	type pidStats struct { cpu, mem float64 }
	pidMap := make(map[int]pidStats)
	for _, line := range psLines {
		fields := strings.Fields(line)
		if len(fields) < 4 { continue }
		pid, _ := strconv.Atoi(fields[1])
		cpu, _ := strconv.ParseFloat(fields[2], 64)
		mem, _ := strconv.ParseFloat(fields[3], 64)
		pidMap[pid] = pidStats{cpu, mem}
	}

	// Get PM2 PIDs via lightweight "pm2 pid" per PM2 app (no jlist)
	pm2Pids := make(map[string]int)
	pm2Names := []string{}
	for _, app := range apps {
		if app.ProcMatch != "" && strings.Contains(app.StatusCmd, "pm2 pid") {
			pm2Names = append(pm2Names, app.ProcMatch)
		}
	}
	if len(pm2Names) > 0 {
		// Build one command that gets all PM2 pids
		var pidCmds []string
		for _, name := range pm2Names {
			pidCmds = append(pidCmds, "echo "+name+":$(/usr/bin/pm2 pid "+name+" 2>/dev/null | head -1)")
		}
		cmd := "export HOME=/root PM2_HOME=/root/.pm2; " + strings.Join(pidCmds, "; ")
		pm2Out, pm2Err := runCmdTimeout(cmd, 5*time.Second)
		if pm2Err == nil {
			for _, line := range strings.Split(strings.TrimSpace(pm2Out), "\n") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					pid, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
					if pid > 0 { pm2Pids[parts[0]] = pid }
				}
			}
		}
	}

	// Match each app's procMatch against ps aux output
	for _, app := range apps {
		if app.ProcMatch == "" { continue }
		re, err := regexp.Compile(app.ProcMatch)
		if err != nil { continue }

		entry := procCacheEntry{}
		for _, line := range psLines {
			if re.MatchString(line) && !strings.Contains(line, "grep") && !strings.Contains(line, "pgrep") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					cpu, _ := strconv.ParseFloat(fields[2], 64)
					mem, _ := strconv.ParseFloat(fields[3], 64)
					entry.Count++
					entry.CPU += cpu
					entry.MemMB += mem
				}
			}
		}

		// If no match from ps aux, try PM2 PID
		if entry.Count == 0 {
			if pid, ok := pm2Pids[app.ProcMatch]; ok {
				if stats, found := pidMap[pid]; found {
					entry.Count = 1
					entry.CPU = stats.cpu
					entry.MemMB = stats.mem
				}
			}
		}

		// Convert mem% to MB
		if memTotalKB > 0 {
			entry.MemMB = entry.MemMB / 100 * float64(memTotalKB) / 1024
		}
		procCache[app.ProcMatch] = entry
	}
	procCacheTime = time.Now()
}

func getProcessStats(procMatch string) (int, float64, float64) {
	if procMatch == "" { return 0, 0, 0 }
	procCacheMu.Lock()
	entry, ok := procCache[procMatch]
	procCacheMu.Unlock()
	if !ok { return 0, 0, 0 }
	return entry.Count, entry.CPU, entry.MemMB
}


func getAppMetrics(metricsCmd string) []AppMetric {
	if metricsCmd == "" { return nil }
	out, err := runCmdTimeout(metricsCmd, 5*time.Second)
	if err != nil { return nil }
	var raw []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil { return nil }
	var metrics []AppMetric
	for _, m := range raw {
		metric := AppMetric{}
		if l, ok := m["label"].(string); ok { metric.Label = l }
		if v, ok := m["value"]; ok {
			switch val := v.(type) {
			case float64: metric.Value = fmt.Sprintf("%.0f", val)
			case string: metric.Value = val
			default: metric.Value = fmt.Sprintf("%v", val)
			}
		}
		if c, ok := m["color"].(string); ok { metric.Color = c }
		metrics = append(metrics, metric)
	}
	return metrics
}

func getSecurityData(metricsCmd string) *SecurityData {
	if metricsCmd == "" { return nil }
	out, err := runCmdTimeout(metricsCmd, 5*time.Second)
	if err != nil { return nil }

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil { return nil }

	sd := &SecurityData{}

	if v, ok := raw["safety_score"].(float64); ok { sd.SafetyScore = int(v) }
	if v, ok := raw["banned_now"].(float64); ok { sd.BannedNow = int(v) }
	if v, ok := raw["banned_total"].(float64); ok { sd.BannedTotal = int(v) }
	if v, ok := raw["ssh_fails_24h"].(float64); ok { sd.SSHFails24h = int(v) }
	if v, ok := raw["probes_24h"].(float64); ok { sd.Probes24h = int(v) }
	if v, ok := raw["blocked_24h"].(float64); ok { sd.Blocked24h = int(v) }
	if v, ok := raw["unique_attackers"].(float64); ok { sd.UniqueAttackers = int(v) }
	if v, ok := raw["last_attack"].(string); ok {
		sd.LastAttack = v
		// Parse and calculate time ago
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", v); err == nil {
			duration := time.Since(t)
			hours := int(duration.Hours())
			mins := int(duration.Minutes()) % 60
			if hours > 24 {
				days := hours / 24
				sd.LastAttackAgo = fmt.Sprintf("%dd ago", days)
			} else if hours > 0 {
				sd.LastAttackAgo = fmt.Sprintf("%dh %dm ago", hours, mins)
			} else {
				sd.LastAttackAgo = fmt.Sprintf("%dm ago", mins)
			}
		}
	}

	// Score color
	if sd.SafetyScore >= 8 {
		sd.ScoreColor = "#00b894"
	} else if sd.SafetyScore >= 5 {
		sd.ScoreColor = "#fdcb6e"
	} else {
		sd.ScoreColor = "#e74c3c"
	}

	// Orphan processes
	if ops, ok := raw["orphan_processes"].([]interface{}); ok {
		for _, o := range ops {
			if om, ok := o.(map[string]interface{}); ok {
				op := OrphanProcess{}
				if v, ok := om["pid"].(float64); ok { op.PID = int(v) }
				if v, ok := om["name"].(string); ok { op.Name = v }
				if v, ok := om["port"].(string); ok { op.Port = v }
				if v, ok := om["user"].(string); ok { op.User = v }
				if v, ok := om["memory"].(string); ok { op.Memory = v }
				if v, ok := om["uptime"].(string); ok { op.Uptime = v }
				sd.OrphanProcesses = append(sd.OrphanProcesses, op)
			}
		}
	}

	// Entry points
	if ep, ok := raw["entry_points"].(map[string]interface{}); ok {
		entryNames := []string{"nginx", "ssh", "fail2ban"}
		for _, name := range entryNames {
			status := "stopped"
			color := "#e74c3c"
			if s, ok := ep[name].(string); ok {
				status = s
				if status == "running" {
					color = "#00b894"
				}
			}
			sd.EntryPoints = append(sd.EntryPoints, EntryPoint{
				Name:   strings.Title(name),
				Status: status,
				Color:  color,
			})
		}
	}

	return sd
}

func parseNginxLogs() map[string][]ErrorURL {
	result := make(map[string][]ErrorURL)

	type appPattern struct {
		name    string
		pattern *regexp.Regexp
	}
	var appPatterns []appPattern

	for _, app := range config.Apps {
		if app.LogPattern != "" {
			patternStr := `(?i)(^|[^a-z0-9])` + regexp.QuoteMeta(app.LogPattern) + `([^a-z0-9]|$)`
			pattern, err := regexp.Compile(patternStr)
			if err == nil {
				appPatterns = append(appPatterns, appPattern{app.Name, pattern})
			}
		}
	}

	today := time.Now().Format("02/Jan/2006")
	yesterday := time.Now().Add(-24 * time.Hour).Format("02/Jan/2006")

	logFiles := []string{
		"/var/log/nginx/access.log",
		"/var/log/nginx/access.log.1",
		"/var/log/nginx/change-requests-access.log",
	}

	type urlInfo struct {
		count    int
		lastTime time.Time
	}
	appErrors := make(map[string]map[string]map[string]*urlInfo)

	for _, app := range config.Apps {
		if app.LogPattern != "" {
			appErrors[app.Name] = map[string]map[string]*urlInfo{
				"5xx": make(map[string]*urlInfo),
				"404": make(map[string]*urlInfo),
				"403": make(map[string]*urlInfo),
			}
		}
	}

	logRegex := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) \d+ "([^"]*)" "([^"]*)"`)

	for _, logFile := range logFiles {
		file, err := os.Open(logFile)
		if err != nil { continue }

		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := scanner.Text()

			if !strings.Contains(line, today) && !strings.Contains(line, yesterday) { continue }
			if !strings.Contains(line, "\" 50") && !strings.Contains(line, "\" 404 ") && !strings.Contains(line, "\" 403 ") { continue }

			matches := logRegex.FindStringSubmatch(line)
			if len(matches) < 7 { continue }

			timestamp := matches[1]
			url := matches[4]
			statusStr := matches[5]
			referer := matches[6]

			var errType string
			if strings.HasPrefix(statusStr, "50") {
				errType = "5xx"
			} else if statusStr == "404" {
				errType = "404"
			} else if statusStr == "403" {
				errType = "403"
			} else {
				continue
			}

			var parsedTime time.Time
			if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestamp); err == nil {
				parsedTime = t
			}

			displayURL := url
			if idx := strings.Index(displayURL, " HTTP"); idx > 0 { displayURL = displayURL[:idx] }
			if idx := strings.Index(displayURL, "?"); idx > 0 { displayURL = displayURL[:idx] }
			if len(displayURL) > 50 { displayURL = displayURL[:50] + "..." }

			for _, ap := range appPatterns {
				if ap.pattern.MatchString(referer) {
					if _, ok := appErrors[ap.name][errType][displayURL]; !ok {
						appErrors[ap.name][errType][displayURL] = &urlInfo{}
					}
					appErrors[ap.name][errType][displayURL].count++
					if !parsedTime.IsZero() {
						appErrors[ap.name][errType][displayURL].lastTime = parsedTime
					}
				}
			}
		}
		file.Close()
	}

	for appName, errTypes := range appErrors {
		var urls []ErrorURL
		for errType, urlMap := range errTypes {
			type kv struct {
				url  string
				info *urlInfo
			}
			var sorted []kv
			for u, i := range urlMap { sorted = append(sorted, kv{u, i}) }
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].info.count > sorted[j].info.count })
			for i := 0; i < 3 && i < len(sorted); i++ {
				ist := time.FixedZone("IST", 5*3600+30*60)
				lastTimeIST := sorted[i].info.lastTime.In(ist).Format("15:04")
				timeAgo := ""
				if !sorted[i].info.lastTime.IsZero() {
					duration := time.Since(sorted[i].info.lastTime)
					hours := int(duration.Hours())
					mins := int(duration.Minutes()) % 60
					if hours > 0 {
						timeAgo = fmt.Sprintf("%dh %dm ago", hours, mins)
					} else {
						timeAgo = fmt.Sprintf("%dm ago", mins)
					}
				}
				urls = append(urls, ErrorURL{
					Type: errType, URL: sorted[i].url, Count: sorted[i].info.count,
					LastTime: lastTimeIST, TimeAgo: timeAgo, Timestamp: sorted[i].info.lastTime,
				})
			}
		}
		sort.Slice(urls, func(i, j int) bool { return urls[i].Timestamp.After(urls[j].Timestamp) })
		result[appName] = urls
	}

	return result
}

func getAppErrorURLs(appName string) []ErrorURL {
	errorURLCacheMu.RLock()
	cacheAge := time.Since(errorURLCacheTime)
	cached, ok := errorURLCache[appName]
	errorURLCacheMu.RUnlock()

	if !ok || cacheAge > 15*time.Minute {
		errorURLCacheMu.Lock()
		if time.Since(errorURLCacheTime) > 15*time.Minute {
			errorURLCache = parseNginxLogs()
			errorURLCacheTime = time.Now()
		}
		cached = errorURLCache[appName]
		errorURLCacheMu.Unlock()
	}

	return cached
}
// getRecentTickets parses nginx logs for recent /seats/ access (JSG Seating only)
func getRecentTickets(logPattern string, limit int) []RecentTicket {
	if logPattern != "jsg1.areakpi.in" { return nil }
	
	var tickets []RecentTicket
	
	out, err := runCmdTimeout("tac /var/log/nginx/access.log | grep /seats/ | head -150", 3*time.Second)
	if err != nil { return nil }
	
		logRegex := regexp.MustCompile(`\[([^\]]+)\] "GET /seats/([A-Z]+-[0-9]+)/[^"]*" \d+ \d+ "[^"]*" "([^"]+)"`)
	
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if len(tickets) >= limit { break }
		
		matches := logRegex.FindStringSubmatch(line)
		if len(matches) < 4 { continue }
		
		timestamp := matches[1]
		code := matches[2]
		userAgent := matches[3]
		
		
		var parsedTime time.Time
		if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestamp); err == nil {
			parsedTime = t
		}
		
		timeAgo := ""
		if !parsedTime.IsZero() {
			duration := time.Since(parsedTime)
			hours := int(duration.Hours())
			mins := int(duration.Minutes()) % 60
			if hours > 0 {
				timeAgo = fmt.Sprintf("%dh %dm ago", hours, mins)
			} else if mins > 0 {
				timeAgo = fmt.Sprintf("%dm ago", mins)
			} else {
				timeAgo = "just now"
			}
		}
		
		device := "Desktop"
		browser := "Unknown"
		ua := strings.ToLower(userAgent)
		
		if strings.Contains(ua, "iphone") {
			device = "iPhone"
		} else if strings.Contains(ua, "ipad") {
			device = "iPad"
		} else if strings.Contains(ua, "android") {
			device = "Android"
		} else if strings.Contains(ua, "macintosh") {
			device = "Mac"
		} else if strings.Contains(ua, "windows") {
			device = "Windows"
		} else if strings.Contains(ua, "linux") {
			device = "Linux"
		}
		
		if strings.Contains(ua, "crios") {
			browser = "Chrome"
		} else if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
			browser = "Chrome"
		} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
			browser = "Safari"
		} else if strings.Contains(ua, "firefox") {
			browser = "Firefox"
		} else if strings.Contains(ua, "edg") {
			browser = "Edge"
		}
		
		tickets = append(tickets, RecentTicket{
			URL:       "/seats/" + code + "/",
			Code:      code,
			Timestamp: parsedTime,
			TimeAgo:   timeAgo,
			Device:    device,
			Browser:   browser,
		})
	}
	
	return tickets
}

// Cached daily ticket logs — refreshed every 5 minutes
var dayLogCache []DayTicketLog
var dayLogCacheTime time.Time
var dayLogCacheMu sync.Mutex

func getDayTicketLogs() []DayTicketLog {
	dayLogCacheMu.Lock()
	defer dayLogCacheMu.Unlock()
	if time.Since(dayLogCacheTime) < 5*time.Minute && dayLogCache != nil { return dayLogCache }

	ist := time.FixedZone("IST", 5*3600+30*60)
	now := time.Now().In(ist)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, ist)

	days := []struct{ label string; start, end time.Time }{
		{"Today", today, now},
		{"Yesterday", today.AddDate(0, 0, -1), today},
		{"2 Days Ago", today.AddDate(0, 0, -2), today.AddDate(0, 0, -1)},
	}

	// Read nginx logs — current, yesterday, and 2-days-ago (gzipped), filter /seats/, exclude bots/curl
	out, err := runCmdTimeout("{ cat /var/log/nginx/access.log /var/log/nginx/access.log.1 2>/dev/null; zcat /var/log/nginx/access.log.2.gz 2>/dev/null; } | grep '/seats/' | grep -v 'curl/' | grep -v 'bot' | grep -v 'Bot' | grep -v 'spider' | grep -v 'crawler'", 5*time.Second)
	if err != nil { return nil }

	logRegex := regexp.MustCompile(`\[([^\]]+)\] "GET /seats/([A-Z]+-[0-9]+)/[^"]*" (\d+) \d+ "[^"]*" "([^"]*)"`)

	type hitEntry struct {
		code string
		ts   time.Time
		ua   string
	}
	var allHits []hitEntry

	for _, line := range strings.Split(out, "\n") {
		matches := logRegex.FindStringSubmatch(line)
		if len(matches) < 5 { continue }
		statusCode := matches[3]
		// Only count 200/304 responses (real page views)
		if statusCode != "200" && statusCode != "304" { continue }
		ua := matches[4]
		// Skip generic/synthetic user agents
		uaLower := strings.ToLower(ua)
		if strings.Contains(uaLower, "curl") || strings.Contains(uaLower, "wget") || strings.Contains(uaLower, "python") || strings.Contains(uaLower, "go-http") || strings.Contains(uaLower, "scan") { continue }
		// Skip truncated/fake user agents (real browsers have Safari/ or Chrome/ version strings)
		if len(ua) < 60 || (!strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Firefox/")) { continue }
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[1])
		if err != nil { continue }
		tIST := t.In(ist)
		// Only keep last 3 days
		if tIST.Before(today.AddDate(0, 0, -2)) { continue }
		allHits = append(allHits, hitEntry{code: matches[2], ts: tIST, ua: ua})
	}

	var result []DayTicketLog
	for _, day := range days {
		// Group hits by code for this day
		type codeStats struct {
			count   int
			lastTS  time.Time
			devices map[string]bool
		}
		grouped := make(map[string]*codeStats)
		totalHits := 0

		for _, h := range allHits {
			if h.ts.Before(day.start) || !h.ts.Before(day.end) { continue }
			totalHits++
			s, ok := grouped[h.code]
			if !ok {
				s = &codeStats{devices: make(map[string]bool)}
				grouped[h.code] = s
			}
			s.count++
			if h.ts.After(s.lastTS) { s.lastTS = h.ts }
			// Parse device
			ua := strings.ToLower(h.ua)
			dev := "Desktop"
			if strings.Contains(ua, "iphone") { dev = "iPhone" } else if strings.Contains(ua, "android") { dev = "Android" } else if strings.Contains(ua, "ipad") { dev = "iPad" } else if strings.Contains(ua, "macintosh") { dev = "Mac" } else if strings.Contains(ua, "windows") { dev = "Windows" }
			s.devices[dev] = true
		}

		// Build sorted hits list
		var hits []TicketHit
		for code, s := range grouped {
			devList := []string{}
			for d := range s.devices { devList = append(devList, d) }
			sort.Strings(devList)
			ago := ""
			dur := time.Since(s.lastTS)
			if dur < time.Hour { ago = fmt.Sprintf("%dm ago", int(dur.Minutes())) } else if dur < 24*time.Hour { ago = fmt.Sprintf("%dh ago", int(dur.Hours())) } else { ago = fmt.Sprintf("%dd ago", int(dur.Hours()/24)) }
			hits = append(hits, TicketHit{
				Code:    code,
				Count:   s.count,
				LastTime: s.lastTS.Format("15:04"),
				LastAgo: ago,
				Devices: strings.Join(devList, ", "),
			})
		}
		// Sort by count descending
		sort.Slice(hits, func(i, j int) bool { return hits[i].Count > hits[j].Count })

		result = append(result, DayTicketLog{
			Label:      day.label,
			Date:       day.start.Format("02 Jan 2006"),
			UniqueHits: len(grouped),
			TotalHits:  totalHits,
			Hits:       hits,
		})
	}

	dayLogCache = result
	dayLogCacheTime = time.Now()
	return result
}

func getReqPerMin(metrics []AppMetric) int {
	for _, m := range metrics {
		if m.Label == "Req/1h" || m.Label == "Req/min" || m.Label == "Requests 1h" || m.Label == "Visitors 1h" {
			val := strings.ReplaceAll(m.Value, ",", "")
			multiplier := 1.0
			if strings.HasSuffix(val, "K") {
				multiplier = 1000
				val = strings.TrimSuffix(val, "K")
			} else if strings.HasSuffix(val, "M") {
				multiplier = 1000000
				val = strings.TrimSuffix(val, "M")
			}
			num, err := strconv.ParseFloat(val, 64)
			if err != nil { continue }
			return int(num * multiplier)
		}
	}
	return 0
}

func getWorkerCount(procMatch string) int {
	if procMatch == "" { return 0 }
	out, err := runCmdTimeout("pgrep -f '"+procMatch+"'", 2*time.Second)
	if err != nil { return 0 }
	pids := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	for _, p := range pids { if p != "" { count++ } }
	if count > 0 { count-- } // Subtract 1 for master process
	return count
}

// Auto-scaling functions
func getAutoScaleState(appName string) *AutoScaleState {
	autoScaleMu.RLock()
	defer autoScaleMu.RUnlock()
	if state, ok := autoScaleStates[appName]; ok {
		return state
	}
	return &AutoScaleState{Enabled: false}
}

func setAutoScaleEnabled(appName string, enabled bool) {
	autoScaleMu.Lock()
	defer autoScaleMu.Unlock()
	if _, ok := autoScaleStates[appName]; !ok {
		autoScaleStates[appName] = &AutoScaleState{}
	}
	autoScaleStates[appName].Enabled = enabled
	if !enabled {
		autoScaleStates[appName].LastAction = "disabled"
		autoScaleStates[appName].LastActionAt = time.Now()
	}
}

func calculateAutoScale(app App, workerCount int, metrics []AppMetric, sysMetrics SystemMetrics) (action string, targetWorkers int, reqRate float64) {
	// Get request rate from metrics
	reqRate = 0
	for _, m := range metrics {
		if m.Label == "Req/min" {
			val := strings.ReplaceAll(m.Value, ",", "")
			if n, err := strconv.ParseFloat(val, 64); err == nil {
				reqRate = n
			}
		}
	}

	if workerCount == 0 {
		return "no_workers", 0, reqRate
	}

	// ENFORCE MINIMUM: Scale up if below configured minimum
	if app.WorkerMin > 0 && workerCount < app.WorkerMin {
		targetWorkers = workerCount + 1
		return "scale_up", targetWorkers, reqRate
	}

	// Calculate req per worker
	reqPerWorker := reqRate / float64(workerCount)

	// Get thresholds (use defaults if not configured)
	upThreshold := app.AutoScaleUpThreshold
	if upThreshold == 0 { upThreshold = 8.0 } // Default: scale up if >8 req/min per worker
	downThreshold := app.AutoScaleDownThreshold
	if downThreshold == 0 { downThreshold = 2.0 } // Default: scale down if <2 req/min per worker

	targetWorkers = workerCount
	action = "optimal"

	// Check if we should scale up
	if reqPerWorker > upThreshold && workerCount < app.WorkerMax {
		// Check server resources before scaling up
		if sysMetrics.CPUPercent < 80 && sysMetrics.MemPercent < 85 {
			targetWorkers = workerCount + 1
			action = "scale_up"
		} else {
			action = "resource_limited"
		}
	}

	// Check if we should scale down
	if reqPerWorker < downThreshold && workerCount > app.WorkerMin {
		targetWorkers = workerCount - 1
		action = "scale_down"
	}

	return action, targetWorkers, reqRate
}

func performAutoScale(app App, action string, targetWorkers int) {
	autoScaleMu.Lock()
	defer autoScaleMu.Unlock()

	if _, ok := autoScaleStates[app.Name]; !ok {
		autoScaleStates[app.Name] = &AutoScaleState{Enabled: true}
	}
	state := autoScaleStates[app.Name]

	// Rate limit: don't scale more than once per 60 seconds
	if time.Since(state.LastActionAt) < 60*time.Second && state.LastAction != "" {
		return
	}

	var cmd string
	if action == "scale_up" {
		if app.WorkerAddCmd != "" {
			cmd = app.WorkerAddCmd
		} else if app.WorkerPidCmd != "" {
			pidOut, _ := runCmdTimeout(app.WorkerPidCmd, 2*time.Second)
			pids := strings.Split(strings.TrimSpace(pidOut), "\n")
			if len(pids) > 0 && pids[0] != "" {
				cmd = "kill -TTIN " + pids[0]
			}
		}
	} else if action == "scale_down" {
		if app.WorkerRemoveCmd != "" {
			cmd = app.WorkerRemoveCmd
		} else if app.WorkerPidCmd != "" {
			pidOut, _ := runCmdTimeout(app.WorkerPidCmd, 2*time.Second)
			pids := strings.Split(strings.TrimSpace(pidOut), "\n")
			if len(pids) > 0 && pids[0] != "" {
				cmd = "kill -TTOU " + pids[0]
			}
		}
	}

	if cmd != "" {
		output, err := runCmdTimeout(cmd, 10*time.Second)
		log.Printf("[AutoScale] %s: %s -> %d workers (cmd: %v, err: %v, out: %s)",
			app.Name, action, targetWorkers, cmd, err, output)
		state.LastAction = action
		state.LastActionAt = time.Now()
		state.TargetWorkers = targetWorkers
	}
}

func getAppStatus(app App) AppStatus {
	status := AppStatus{App: app, Status: "stopped", CanScale: app.WorkerPidCmd != "" || app.WorkerAddCmd != ""}
	if app.StatusCmd != "" {
		_, err := runCmdTimeout(app.StatusCmd, 3*time.Second)
		if err == nil { status.Status = "running" }
	}
	if app.ProcMatch != "" {
		count, cpu, mem := getProcessStats(app.ProcMatch)
		status.ProcCount = count
		status.CPUPercent = cpu
		status.MemMB = mem
	}

	// Disk size from cache
	if app.WorkDir != "" {
		diskCacheMu.Lock()
		if d, ok := diskCache[app.WorkDir]; ok { status.DiskSize = d }
		diskCacheMu.Unlock()
	}

	// Handle Security Dashboard specially
	if app.IsSecurityDashboard {
		status.Security = getSecurityData(app.MetricsCmd)
	} else if app.MetricsCmd != "" {
		status.Metrics = getAppMetrics(app.MetricsCmd)
	}

	if app.WorkerCountCmd != "" {
		out, err := runCmdTimeout(app.WorkerCountCmd, 3*time.Second)
		if err == nil {
			if n, e := strconv.Atoi(strings.TrimSpace(out)); e == nil { status.WorkerCount = n }
		}
	} else if app.WorkerPidCmd != "" {
		status.WorkerCount = getWorkerCount(app.ProcMatch)
	}
	if app.LogPattern != "" { status.ErrorURLs = getAppErrorURLs(app.Name) }
	if app.LogPattern == "jsg1.areakpi.in" { status.DayLogs = getDayTicketLogs() }
	ist := time.FixedZone("IST", 5*3600+30*60)
	status.RefreshTime = time.Now().In(ist).Format("15:04:05")

	// Get auto-scaling state if app supports scaling
	if status.CanScale {
		state := getAutoScaleState(app.Name)
		status.AutoScale = &AutoScaleState{
			Enabled:       state.Enabled,
			LastAction:    state.LastAction,
			LastActionAt:  state.LastActionAt,
			LastReqRate:   state.LastReqRate,
			TargetWorkers: state.TargetWorkers,
			ReqPerWorker:  state.ReqPerWorker,
			CooldownSecs:  state.CooldownSecs,
			LastScaleDesc: state.LastScaleDesc,
			BusyWorkers:   state.BusyWorkers,
			IdleWorkers:   state.IdleWorkers,
		}
	}

	// Check worker alerts (runs in background, won't block)
	go checkWorkerAlerts(app, status.WorkerCount)

	// Check for app crash (only for non-security-dashboard apps with a status command)
	if app.StatusCmd != "" && !app.IsSecurityDashboard {
		go checkAppCrash(app.Name, status.Status)
	}

	return status
}

// Separate function to run auto-scaling (called from indexHandler with system metrics)
func runAutoScaleCheck(app App, status *AppStatus, sysMetrics SystemMetrics) {
	if !status.CanScale { return }

	// CRITICAL: Check config FIRST - if disabled in config, NEVER auto-scale
	if !app.AutoScaleEnabled {
		status.AutoScale = &AutoScaleState{Enabled: false}
		return
	}
	state := getAutoScaleState(app.Name)
	if !state.Enabled {
		// Still populate basic metrics even when disabled
		status.AutoScale = &AutoScaleState{Enabled: false}
		return
	}

	action, targetWorkers, reqRate := calculateAutoScale(app, status.WorkerCount, status.Metrics, sysMetrics)

	// Calculate enhanced metrics
	reqPerWorker := float64(0)
	if status.WorkerCount > 0 {
		reqPerWorker = reqRate / float64(status.WorkerCount)
	}

	// Calculate cooldown
	cooldownSecs := 0
	if !state.LastActionAt.IsZero() {
		elapsed := time.Since(state.LastActionAt)
		if elapsed < 60*time.Second {
			cooldownSecs = int((60*time.Second - elapsed).Seconds())
		}
	}

	// Estimate busy/idle workers based on CPU usage
	// If CPU > 0, assume at least 1 worker is busy; scale with CPU %
	busyWorkers := 0
	if status.CPUPercent > 0 && status.WorkerCount > 0 {
		// Rough estimate: if 50% CPU with 2 workers, ~1 is busy
		busyWorkers = int((status.CPUPercent / 100.0) * float64(status.WorkerCount) + 0.5)
		if busyWorkers > status.WorkerCount { busyWorkers = status.WorkerCount }
		if busyWorkers < 1 && status.CPUPercent > 0 { busyWorkers = 1 }
	}
	idleWorkers := status.WorkerCount - busyWorkers

	// Update state with current calculation
	autoScaleMu.Lock()
	if _, ok := autoScaleStates[app.Name]; !ok {
		autoScaleStates[app.Name] = &AutoScaleState{Enabled: true}
	}
	s := autoScaleStates[app.Name]
	s.LastReqRate = reqRate
	s.TargetWorkers = targetWorkers
	s.ReqPerWorker = reqPerWorker
	s.CooldownSecs = cooldownSecs
	s.BusyWorkers = busyWorkers
	s.IdleWorkers = idleWorkers
	if action != "scale_up" && action != "scale_down" {
		s.LastAction = action
	}
	autoScaleMu.Unlock()

	// Perform scaling if needed
	if action == "scale_up" || action == "scale_down" {
		// Store previous worker count for LastScaleDesc
		prevWorkers := status.WorkerCount
		performAutoScale(app, action, targetWorkers)
		// Update LastScaleDesc after scaling
		autoScaleMu.Lock()
		if action == "scale_up" {
			autoScaleStates[app.Name].LastScaleDesc = fmt.Sprintf("↑ %d→%d", prevWorkers, targetWorkers)
		} else {
			autoScaleStates[app.Name].LastScaleDesc = fmt.Sprintf("↓ %d→%d", prevWorkers, targetWorkers)
		}
		autoScaleMu.Unlock()
	}

	// Update status for display
	status.AutoScale = getAutoScaleState(app.Name)
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == "authenticated" {
			// Refresh cookie on every request so session never expires while active
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authenticated", Path: "/", MaxAge: 86400 * 365, HttpOnly: true})
			next(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(config.Password)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authenticated", Path: "/", MaxAge: 86400 * 365, HttpOnly: true})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Login</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#f5f3ef;color:#eee;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}.login-box{background:#fff;padding:40px;border-radius:12px;width:100%;max-width:360px}h1{margin:0 0 25px;color:#2c5f8a;font-size:1.5em;text-align:center}input{padding:14px;width:100%;border:none;border-radius:8px;margin-bottom:15px;font-size:16px;background:#f0ede8;color:#fff}button{padding:14px;width:100%;background:#e94560;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:16px;font-weight:600}</style></head><body><div class="login-box"><h1>Server Control</h1><form method="POST"><input type="password" name="password" placeholder="Password" autofocus><button type="submit">Login</button></form></div></body></html>`)
}

// Static loading screen HTML — sent instantly before data gathering
const loadingHTML = `<!DOCTYPE html><html><head><title>Server Control</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box}body{font-family:Georgia,'Times New Roman',serif;background:#f5f3ef;color:#2c2c2c;margin:0;padding:0;overflow-x:hidden}#loader{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;gap:20px}.loader-title{color:#8b4513;font-size:1.4em;font-weight:bold;letter-spacing:.5px}.loader-bar{width:220px;height:3px;background:#e8e4de;border-radius:2px;overflow:hidden}.loader-fill{height:100%;background:linear-gradient(90deg,#8b4513,#2c5f8a,#1a7a5a,#8b4513);background-size:200% 100%;width:100%;border-radius:2px;animation:shimmer 1.5s ease-in-out infinite}@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}.loader-text{color:#999;font-size:.8em}.loader-dots{display:inline-block}.loader-dots::after{content:'';animation:dots 1.5s steps(4,end) infinite}@keyframes dots{0%{content:''}25%{content:'.'}50%{content:'..'}75%{content:'...'}}</style></head><body><div id="loader"><div class="loader-title">Server Control</div><div class="loader-bar"><div class="loader-fill"></div></div><div class="loader-text">Loading <span class="loader-dots"></span></div></div>`

func indexHandler(w http.ResponseWriter, r *http.Request) {
	// Phase 1: Send loading screen immediately
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Transfer-Encoding", "chunked")
	fmt.Fprint(w, loadingHTML)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	// Phase 2: Gather data (this takes 1-3 seconds)
	metrics := getSystemMetrics()

	// Check system resource alerts (CPU/RAM at 50%, 70%, 90%)
	go checkSystemResourceAlerts(metrics)

	// Refresh caches ONCE for all apps
	refreshProcessCache(config.Apps)
	refreshDiskCache(config.Apps)

	// Gather all app statuses in parallel
	type indexedStatus struct {
		idx    int
		status AppStatus
	}
	ch := make(chan indexedStatus, len(config.Apps))
	for i, app := range config.Apps {
		go func(idx int, a App) {
			s := getAppStatus(a)
			if s.CanScale {
				runAutoScaleCheck(a, &s, metrics)
			}
			ch <- indexedStatus{idx, s}
		}(i, app)
	}

	allStatuses := make([]AppStatus, len(config.Apps))
	for range config.Apps {
		res := <-ch
		allStatuses[res.idx] = res.status
	}
	var apps []AppStatus
	var securityApp *AppStatus
	for _, status := range allStatuses {
		if status.App.IsSecurityDashboard {
			securityApp = &status
		} else {
			apps = append(apps, status)
		}
	}

	// Sort regular apps by activity
	sort.Slice(apps, func(i, j int) bool {
		return getReqPerMin(apps[i].Metrics) > getReqPerMin(apps[j].Metrics)
	})

	// Append security dashboard at the end if it exists
	if securityApp != nil {
		apps = append(apps, *securityApp)
	}

	// Extract orphan processes for quick controls display
	var orphans []OrphanProcess
	for _, a := range apps {
		if a.Security != nil && len(a.Security.OrphanProcesses) > 0 {
			orphans = a.Security.OrphanProcesses
			break
		}
	}
	data := struct { Metrics SystemMetrics; Apps []AppStatus; Orphans []OrphanProcess }{metrics, apps, orphans}
	funcMap := template.FuncMap{
		"contains": strings.Contains,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
		"hasURLMetrics": func(metrics []AppMetric) bool {
			for _, m := range metrics {
				if strings.HasSuffix(m.Label, "URLs") { return true }
			}
			return false
		},
		"errorColor": func(errType string) string {
			switch errType {
			case "5xx": return "#e74c3c"
			case "404": return "#f39c12"
			case "403": return "#9b59b6"
			default: return "#888"
			}
		},
		"timeAgo": func(t time.Time) string {
			if t.IsZero() { return "never" }
			d := time.Since(t)
			if d < time.Minute { return "just now" }
			if d < time.Hour { return fmt.Sprintf("%dm ago", int(d.Minutes())) }
			return fmt.Sprintf("%dh ago", int(d.Hours()))
		},
	}
	tmpl := `<meta http-equiv="refresh" content="30"><style>#loader{display:none!important}body{font-family:Georgia,'Times New Roman',serif;background:#f5f3ef;color:#2c2c2c;padding:15px}h1{color:#8b4513;font-size:1.4em;margin:0 0 15px;letter-spacing:.5px}.header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:15px}.header-links a{color:#2c5f8a;text-decoration:none;margin-left:15px;font-size:.9em}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}.metric{background:#fff;padding:15px;border-radius:10px;text-align:center;border:1px solid #e8e4de;box-shadow:0 1px 3px rgba(0,0,0,.06)}.metric-value{font-size:1.8em;font-weight:bold}.metric-label{font-size:.75em;color:#888;margin-top:5px}.metric-sub{font-size:.7em;color:#999}.green{color:#1a7a5a}.yellow{color:#b8860b}.red{color:#c0392b}.apps{display:grid;gap:12px}.app{background:#fff;padding:15px;border-radius:10px;border:1px solid #e8e4de;box-shadow:0 1px 3px rgba(0,0,0,.06)}.app-header{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:10px}.app-name{font-size:1.1em;font-weight:600;color:#2c5f8a;flex:1}.status{padding:4px 12px;border-radius:15px;font-size:.75em;font-weight:600;color:#fff}.status.running{background:#1a7a5a}.status.stopped{background:#c0392b}.app-desc{color:#777;font-size:.85em;margin-bottom:10px}.app-stats{display:flex;gap:10px;font-size:.8em;color:#999;margin-bottom:12px;flex-wrap:wrap}.app-stats span{background:#f0ede8;padding:4px 10px;border-radius:5px}.app-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:12px}.error-urls{background:#f0ede8;border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:.75em}.error-urls-title{font-weight:600;margin-bottom:6px}.error-urls-row{display:flex;gap:8px;margin-bottom:4px;align-items:baseline}.error-urls-label{min-width:60px;font-weight:500}.error-urls-value{color:#999;word-break:break-all}.error-section{background:#f0ede8;border-radius:8px;padding:12px;margin-bottom:12px;width:100%}.error-section-title{font-weight:600;margin-bottom:8px;font-size:.85em;color:#777}.error-row{display:flex;gap:12px;margin-bottom:6px;font-size:.8em;align-items:baseline}.error-type{min-width:40px;font-weight:600}.error-url{flex:1;color:#999;word-break:break-all;font-family:monospace;font-size:.9em}.error-meta{color:#888;white-space:nowrap;font-size:.9em}.app-metric{background:#f0ede8;padding:10px 8px;border-radius:8px;text-align:center}.app-metric-value{font-size:1.3em;font-weight:bold;color:#2c2c2c}.app-metric-label{font-size:.65em;color:#888;margin-top:3px}.worker-control{display:flex;align-items:center;gap:8px;background:#f0ede8;padding:8px 12px;border-radius:8px;margin-bottom:12px}.worker-control span{font-size:.85em;color:#7b5ea7}.worker-btn{width:28px;height:28px;border:none;border-radius:6px;cursor:pointer;font-size:1.1em;font-weight:bold;display:flex;align-items:center;justify-content:center}.worker-btn.add{background:#1a7a5a;color:#fff}.worker-btn.remove{background:#c0392b;color:#fff}.worker-btn:disabled{opacity:.3;cursor:not-allowed}.worker-count{font-size:1.2em;font-weight:bold;color:#7b5ea7;min-width:20px;text-align:center}.deps{font-size:.75em;color:#999;margin-bottom:12px}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{padding:10px 18px;border:none;border-radius:6px;cursor:pointer;font-size:.85em;font-weight:600;flex:1;min-width:80px;display:flex;align-items:center;justify-content:center;gap:8px}.btn-start{background:#1a7a5a;color:#fff}.btn-stop{background:#c0392b;color:#fff}.btn-restart{background:#d4a84b;color:#fff}.btn:disabled{opacity:.4;cursor:not-allowed}.btn.loading{opacity:.7;cursor:wait}.spinner{width:14px;height:14px;border:2px solid transparent;border-top-color:currentColor;border-radius:50%;animation:spin .8s linear infinite;display:none}.btn.loading .spinner{display:inline-block}.btn.loading .btn-text{display:none}@keyframes spin{to{transform:rotate(360deg)}}.security-dashboard{background:linear-gradient(135deg,#fff 0%,#f8f6f2 100%);border:1px solid #d4cec4}.security-score{display:flex;align-items:center;gap:20px;margin-bottom:15px}.score-circle{width:80px;height:80px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:2em;font-weight:bold;border:4px solid}.score-label{font-size:.9em;color:#888}.score-desc{font-size:.75em;color:#999;margin-top:4px}.security-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:10px;margin-bottom:15px}.security-stat{background:#f0ede8;padding:12px;border-radius:8px;text-align:center}.security-stat-value{font-size:1.4em;font-weight:bold}.security-stat-label{font-size:.7em;color:#888;margin-top:4px}.entry-points{background:#f0ede8;border-radius:8px;padding:12px;margin-bottom:12px}.entry-points-title{font-weight:600;margin-bottom:10px;font-size:.85em;color:#777}.entry-point{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:#fff;border-radius:6px;border:1px solid #e8e4de;margin-right:8px;margin-bottom:6px;font-size:.85em}.entry-point-dot{width:8px;height:8px;border-radius:50%}.last-attack{background:#f0ede8;border-radius:8px;padding:10px 12px;margin-bottom:12px;font-size:.8em;color:#888}.last-attack span{color:#b8700d}html{overflow-x:hidden}@media(max-width:480px){body{padding:10px;max-width:100vw;overflow-x:hidden}.metric-value{font-size:1.5em}.btn{padding:12px 10px;font-size:.75em;min-width:60px}.app-metrics{grid-template-columns:repeat(3,1fr)}.score-circle{width:60px;height:60px;font-size:1.5em}.app{overflow:hidden}.actions{flex-wrap:nowrap}.error-urls-value{font-size:.75em}}.qc{background:#fff;border-radius:10px;padding:12px;margin-bottom:20px;border:1px solid #e8e4de;box-shadow:0 1px 3px rgba(0,0,0,.06)}.qc-title{font-size:.85em;font-weight:600;color:#2c5f8a;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}.qc-title span{font-size:.75em;color:#999;font-weight:400}.qc-row{display:flex;align-items:center;gap:6px;padding:6px 0;border-bottom:1px solid #f0ede8;font-size:.75em}.qc-row:last-child{border-bottom:none}.qc-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.qc-dot.running{background:#1a7a5a}.qc-dot.stopped{background:#c0392b}.qc-name{flex:1;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}.qc-stats{display:flex;gap:8px;color:#888;font-size:.9em;flex-shrink:0}.qc-stat{min-width:45px;text-align:right}.qc-actions{display:flex;gap:3px;flex-shrink:0}.qc-btn{width:24px;height:24px;border:none;border-radius:4px;cursor:pointer;font-size:.7em;font-weight:700;display:flex;align-items:center;justify-content:center;color:#fff}.qc-btn.s{background:#1a7a5a}.qc-btn.x{background:#c0392b}.qc-btn.r{background:#d4a84b;color:#fff}.qc-btn:disabled{opacity:.3;cursor:not-allowed}.pr{background:#fff;border-radius:10px;padding:12px;margin-bottom:20px;border:1px solid #e8e4de;box-shadow:0 1px 3px rgba(0,0,0,.06)}.pr-title{font-size:.85em;font-weight:600;color:#b8700d;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}.pr-title span{font-size:.75em;color:#999;font-weight:400}.pr-hdr{display:flex;gap:6px;padding:6px 0;border-bottom:2px solid #e8e4de;margin-bottom:4px;font-size:.7em;color:#999;font-weight:600}.pr-hdr-port{min-width:50px}.pr-hdr-name{flex:1}.pr-hdr-procs{min-width:45px;text-align:right}.pr-hdr-status{min-width:55px;text-align:center}.pr-row{display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid #f0ede8;font-size:.75em}.pr-row:last-child{border-bottom:none}.pr-port{min-width:50px;font-family:monospace;font-weight:600;color:#b8700d}.pr-name{flex:1;color:#444;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.pr-procs{min-width:45px;text-align:right;color:#888}.pr-status{min-width:55px;text-align:center}.op{background:#fff;border-radius:10px;padding:12px;margin-bottom:20px;border-left:3px solid #b8700d;border:1px solid #e8e4de;border-left:3px solid #b8700d;box-shadow:0 1px 3px rgba(0,0,0,.06)}.op-title{font-size:.85em;font-weight:600;color:#b8700d;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center}.op-title span{font-size:.75em;color:#999;font-weight:400}.op-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid #f0ede8;font-size:.75em}.op-row:last-child{border-bottom:none}.op-port{min-width:45px;font-family:monospace;font-weight:600;color:#b8700d}.op-name{min-width:80px;color:#2c5f8a;font-weight:500}.op-pid{color:#7b5ea7;min-width:65px}.op-meta{color:#888;display:flex;gap:10px;flex:1}.op-none{color:#1a7a5a;font-size:.8em;padding:8px 0}</style><div class="header"><h1>Server Control</h1><div class="header-links"><a href="/">Refresh</a> <a href="/logout">Logout</a></div></div><div class="metrics"><div class="metric"><div class="metric-value {{if lt .Metrics.CPUPercent 50.0}}green{{else if lt .Metrics.CPUPercent 80.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.CPUPercent}}%</div><div class="metric-label">CPU</div><div class="metric-sub">Load: {{.Metrics.LoadAvg}}</div></div><div class="metric"><div class="metric-value {{if lt .Metrics.MemPercent 70.0}}green{{else if lt .Metrics.MemPercent 90.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.MemPercent}}%</div><div class="metric-label">RAM</div><div class="metric-sub">{{printf "%.1f" .Metrics.MemUsedGB}}/{{printf "%.1f" .Metrics.MemTotalGB}} GB</div></div><div class="metric"><div class="metric-value {{if lt .Metrics.DiskPercent 70.0}}green{{else if lt .Metrics.DiskPercent 90.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.DiskPercent}}%</div><div class="metric-label">Disk</div><div class="metric-sub">{{printf "%.0f" .Metrics.DiskUsedGB}}/{{printf "%.0f" .Metrics.DiskTotalGB}} GB</div></div><div class="metric"><div class="metric-value green">{{.Metrics.Uptime}}</div><div class="metric-label">Uptime</div></div></div><div class="qc"><div class="qc-title">Quick Controls <span>{{len .Apps}} apps</span></div><div class="qc-row" style="border-bottom:2px solid #e8e4de;padding-bottom:8px;margin-bottom:4px"><span class="qc-dot" style="visibility:hidden"></span><span class="qc-name" style="color:#999;font-size:.7em;font-weight:600">APP NAME</span><div class="qc-stats"><span class="qc-stat qc-sort" data-col="cpu" style="color:#999;font-size:.8em;font-weight:600;cursor:pointer">CPU ⇅</span><span class="qc-stat qc-sort" data-col="ram" style="color:#999;font-size:.8em;font-weight:600;cursor:pointer">RAM ⇅</span><span class="qc-stat qc-sort" data-col="disk" style="color:#999;font-size:.8em;font-weight:600;cursor:pointer">Disk ⇅</span></div><div class="qc-actions" style="visibility:hidden"><span class="qc-btn s">.</span><span class="qc-btn x">.</span><span class="qc-btn r">.</span></div></div>{{range .Apps}}{{if not .App.IsSecurityDashboard}}{{if eq .Status "running"}}<div class="qc-row" data-cpu="{{printf "%.1f" .CPUPercent}}" data-ram="{{printf "%.0f" .MemMB}}" data-disk="{{.DiskSize}}"><span class="qc-dot {{.Status}}"></span><span class="qc-name">{{.App.Name}}</span><div class="qc-stats"><span class="qc-stat" style="color:{{if gt .CPUPercent 50.0}}#c0392b{{else if gt .CPUPercent 10.0}}#b8860b{{else}}#777{{end}}">{{if gt .CPUPercent 0.0}}{{printf "%.0f" .CPUPercent}}%{{else}}-{{end}}</span><span class="qc-stat" style="color:{{if gt .MemMB 500.0}}#c0392b{{else if gt .MemMB 200.0}}#b8860b{{else}}#777{{end}}">{{if gt .MemMB 0.0}}{{printf "%.0f" .MemMB}}M{{else}}-{{end}}</span><span class="qc-stat" style="color:#999">{{if .DiskSize}}{{.DiskSize}}{{else}}-{{end}}</span></div><div class="qc-actions"><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="start"><button class="qc-btn s" {{if eq .Status "running"}}disabled{{end}} title="Start">▶</button></form><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="stop"><button class="qc-btn x" {{if eq .Status "stopped"}}disabled{{end}} title="Stop">■</button></form><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="restart"><button class="qc-btn r" title="Restart">↻</button></form></div></div>{{end}}{{end}}{{end}}</div><div class="qc" style="margin-top:10px;opacity:.7"><div class="qc-title" style="color:#888">Inactive <span>{{range $i, $a := .Apps}}{{if not $a.App.IsSecurityDashboard}}{{if eq $a.Status "stopped"}}{{end}}{{end}}{{end}}</span></div>{{range .Apps}}{{if not .App.IsSecurityDashboard}}{{if eq .Status "stopped"}}<div class="qc-row" data-cpu="0" data-ram="0" data-disk="{{.DiskSize}}"><span class="qc-dot {{.Status}}"></span><span class="qc-name" style="color:#888">{{.App.Name}}</span><div class="qc-stats"><span class="qc-stat" style="color:#999">-</span><span class="qc-stat" style="color:#999">-</span><span class="qc-stat" style="color:#999">{{if .DiskSize}}{{.DiskSize}}{{else}}-{{end}}</span></div><div class="qc-actions"><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="start"><button class="qc-btn s" title="Start">▶</button></form><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="stop"><button class="qc-btn x" disabled title="Stop">■</button></form><form method="POST" action="/action" class="action-form" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="restart"><button class="qc-btn r" title="Restart">↻</button></form></div></div>{{end}}{{end}}{{end}}</div><script>function parseDisk(v){if(!v||v==="-")return 0;var n=parseFloat(v)||0;if(v.indexOf("G")>-1||v.indexOf("g")>-1)return n*1024;if(v.indexOf("K")>-1||v.indexOf("k")>-1)return n/1024;return n}var sortDir={};document.querySelectorAll(".qc-sort").forEach(function(h){h.addEventListener("click",function(){var col=h.dataset.col;sortDir[col]=!sortDir[col];var qc=h.closest(".qc");var rows=Array.from(qc.querySelectorAll(".qc-row[data-cpu]"));rows.sort(function(a,b){var av,bv;if(col==="disk"){av=parseDisk(a.dataset.disk);bv=parseDisk(b.dataset.disk)}else{av=parseFloat(a.dataset[col])||0;bv=parseFloat(b.dataset[col])||0}return sortDir[col]?av-bv:bv-av});rows.forEach(function(r){qc.appendChild(r)});document.querySelectorAll(".qc-sort").forEach(function(s){var t=s.textContent.replace(/ [↑↓⇅]/,"");s.textContent=t+" ⇅"});var t=h.textContent.replace(/ [↑↓⇅]/,"");h.textContent=t+(sortDir[col]?" ↑":" ↓")})})</script><div class="pr"><div class="pr-title">Port Reference <span>sorted by port</span></div><div class="pr-hdr"><span class="pr-hdr-port">PORT</span><span class="pr-hdr-name">APP</span><span class="pr-hdr-procs">PROCS</span><span class="pr-hdr-status">STATUS</span></div>{{range .Apps}}{{if .App.Port}}<div class="pr-row"><span class="pr-port">{{.App.Port}}</span><span class="pr-name">{{.App.Name}}</span><span class="pr-procs">{{if gt .ProcCount 0}}{{.ProcCount}}{{else}}-{{end}}</span><span class="pr-status"><span class="qc-dot {{.Status}}" style="display:inline-block"></span></span></div>{{end}}{{end}}</div><script>(function(){var pr=document.querySelector(".pr");if(!pr)return;var rows=Array.from(pr.querySelectorAll(".pr-row"));rows.sort(function(a,b){var ap=parseInt(a.querySelector(".pr-port").textContent)||99999;var bp=parseInt(b.querySelector(".pr-port").textContent)||99999;return ap-bp});rows.forEach(function(r){pr.appendChild(r)})})()</script><div class="op"><div class="op-title">Orphan Processes <span>unmanaged listeners</span></div>{{if .Orphans}}{{range .Orphans}}<div class="op-row"><span class="op-port">:{{.Port}}</span><span class="op-name">{{.Name}}</span><span class="op-pid">PID {{.PID}}</span><div class="op-meta"><span>{{.User}}</span><span>{{.Memory}}</span><span style="color:#1a7a5a">{{.Uptime}}</span></div><form method="POST" action="/kill-orphan" style="margin:0" onsubmit="return confirm('Kill PID {{.PID}} ({{.Name}}) on port {{.Port}}?')"><input type="hidden" name="pid" value="{{.PID}}"><button type="submit" style="background:#c0392b;color:#fff;border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:.7em;font-weight:600;white-space:nowrap">Kill</button></form></div>{{end}}{{else}}<div class="op-none">No orphan processes detected</div>{{end}}</div><div class="apps">{{range .Apps}}<div class="app {{if .App.IsSecurityDashboard}}security-dashboard{{end}}"><div class="app-header"><span class="app-name">{{if .App.IsSecurityDashboard}}🛡️ {{end}}{{.App.Name}}</span><span class="status {{.Status}}">{{.Status}}</span></div><div class="app-desc">{{.App.Description}} <span style="color:#999;font-size:.75em;margin-left:8px">refreshed @{{.RefreshTime}} IST</span></div>{{if .App.IsSecurityDashboard}}{{if .Security}}<div class="security-score"><div class="score-circle" style="border-color:{{.Security.ScoreColor}};color:{{.Security.ScoreColor}}">{{.Security.SafetyScore}}</div><div><div class="score-label">Safety Score</div><div class="score-desc">{{if ge .Security.SafetyScore 8}}Server is well protected{{else if ge .Security.SafetyScore 5}}Moderate risk detected{{else}}High risk - action needed{{end}}</div></div></div><div class="security-grid"><div class="security-stat"><div class="security-stat-value" style="color:#c0392b">{{.Security.BannedNow}}</div><div class="security-stat-label">Banned Now</div></div><div class="security-stat"><div class="security-stat-value" style="color:#7b5ea7">{{.Security.BannedTotal}}</div><div class="security-stat-label">Total Banned</div></div><div class="security-stat"><div class="security-stat-value" style="color:#b8860b">{{.Security.Probes24h}}</div><div class="security-stat-label">Probes 24h</div></div><div class="security-stat"><div class="security-stat-value" style="color:#1a7a5a">{{.Security.Blocked24h}}</div><div class="security-stat-label">Blocked 24h</div></div><div class="security-stat"><div class="security-stat-value" style="color:#b8700d">{{.Security.UniqueAttackers}}</div><div class="security-stat-label">Attackers</div></div><div class="security-stat"><div class="security-stat-value" style="color:#2c5f8a">{{.Security.SSHFails24h}}</div><div class="security-stat-label">SSH Fails</div></div></div><div class="entry-points"><div class="entry-points-title">Entry Points</div>{{range .Security.EntryPoints}}<span class="entry-point"><span class="entry-point-dot" style="background:{{.Color}}"></span><span style="color:{{.Color}}">{{.Name}}</span></span>{{end}}</div>{{if .Security.LastAttackAgo}}<div class="last-attack">Last probe: <span>{{.Security.LastAttackAgo}}</span></div>{{end}}{{if .Security.OrphanProcesses}}<div class="error-section" style="border-left:3px solid #e67e22"><div class="error-section-title" style="color:#b8700d">Orphan Processes ({{len .Security.OrphanProcesses}} unmanaged)</div>{{range .Security.OrphanProcesses}}<div class="error-row" style="align-items:center"><span class="error-type" style="color:#b8700d;min-width:50px">:{{.Port}}</span><span style="color:#2c5f8a;min-width:80px;font-weight:600">{{.Name}}</span><span style="color:#7b5ea7;min-width:50px">PID {{.PID}}</span><span class="error-meta"><span style="color:#888">{{.User}}</span> <span style="color:#999">{{.Memory}}</span> <span style="color:#1a7a5a">[{{.Uptime}}]</span></span><form method="POST" action="/kill-orphan" style="margin:0" onsubmit="return confirm('Kill PID {{.PID}} ({{.Name}})?')"><input type="hidden" name="pid" value="{{.PID}}"><button type="submit" style="background:#c0392b;color:#fff;border:none;padding:3px 8px;border-radius:4px;cursor:pointer;font-size:.7em;font-weight:600">Kill</button></form></div>{{end}}</div>{{end}}{{end}}{{else}}{{if or (gt .ProcCount 0) (gt .MemMB 0.0)}}<div class="app-stats">{{if gt .ProcCount 0}}<span>CPU: {{printf "%.1f" .CPUPercent}}%</span>{{end}}{{if gt .MemMB 0.0}}<span>RAM: {{printf "%.0f" .MemMB}} MB</span>{{end}}{{if gt .ProcCount 0}}<span>Procs: {{.ProcCount}}</span>{{end}}</div>{{end}}{{if .Metrics}}<div class="app-metrics">{{range .Metrics}}{{if not (contains .Label "URLs")}}<div class="app-metric"><div class="app-metric-value" {{if .Color}}style="color: {{.Color}}"{{end}}>{{.Value | safeHTML}}</div><div class="app-metric-label">{{.Label}}</div></div>{{end}}{{end}}</div>{{if hasURLMetrics .Metrics}}<div class="error-urls"><div class="error-urls-title">Error Details (24h)</div>{{range .Metrics}}{{if contains .Label "URLs"}}<div class="error-urls-row"><span class="error-urls-label" {{if .Color}}style="color:{{.Color}}"{{end}}>{{.Label}}:</span><span class="error-urls-value">{{.Value}}</span></div>{{end}}{{end}}</div>{{end}}{{end}}{{if .DayLogs}}{{range .DayLogs}}<div class="error-section" style="border-left:3px solid #3498db"><div class="error-section-title" style="color:#2c5f8a;display:flex;justify-content:space-between">📊 {{.Label}} — {{.Date}} <span style="color:#888;font-weight:400">{{.UniqueHits}} unique · {{.TotalHits}} total</span></div>{{if .Hits}}<div style="max-height:180px;overflow-y:auto">{{range .Hits}}<div class="error-row"><span class="error-type" style="color:#2c5f8a;min-width:55px">{{.Code}}</span><span style="color:#7b5ea7;min-width:30px;font-weight:600">×{{.Count}}</span><span class="error-meta"><span style="color:#1a7a5a">[{{.LastAgo}}]</span> <span style="color:#888">{{.LastTime}}</span> <span style="color:#999">{{.Devices}}</span></span></div>{{end}}</div>{{else}}<div style="color:#999;font-size:.85em">No hits</div>{{end}}</div>{{end}}{{end}}{{if .App.LogPattern}}<div class="error-section"><div class="error-section-title">Error URLs (24h)</div>{{if .ErrorURLs}}{{range .ErrorURLs}}<div class="error-row"><span class="error-type" style="color:{{errorColor .Type}}">{{.Type}}</span><span class="error-url">{{.URL}}</span><span class="error-meta"><span style="color:#b8700d;font-weight:600">[{{.TimeAgo}}]</span> <span style="color:#2c5f8a">@{{.LastTime}} IST</span> ({{.Count}})</span></div>{{end}}{{else}}<div style="color:#1a7a5a;font-size:.85em">✓ No errors</div>{{end}}</div>{{end}}{{if .CanScale}}<div class="worker-control"><span>Workers:</span><form method="POST" action="/action" style="display:inline"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="remove_worker"><button type="submit" class="worker-btn remove" {{if le .WorkerCount .App.WorkerMin}}disabled{{end}} title="Remove worker (min: {{.App.WorkerMin}}){{if and .AutoScale .AutoScale.Enabled}} • Auto active{{end}}">−</button></form><span class="worker-count">{{.WorkerCount}}</span><form method="POST" action="/action" style="display:inline"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="add_worker"><button type="submit" class="worker-btn add" {{if ge .WorkerCount .App.WorkerMax}}disabled{{end}} title="Add worker (max: {{.App.WorkerMax}}){{if and .AutoScale .AutoScale.Enabled}} • Auto active{{end}}">+</button></form><span style="font-size:.65em;color:#999;margin-left:auto">{{if and .AutoScale .AutoScale.Enabled}}⚡ Auto{{else}}Manual{{end}} • max {{.App.WorkerMax}}</span></div><div class="autoscale-card" style="background:linear-gradient(135deg,#f8f6f2 0%,#fff 100%);border:1px solid {{if and .AutoScale .AutoScale.Enabled}}#00b894{{else}}#444{{end}};border-radius:8px;padding:12px;margin-bottom:12px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><span style="font-weight:600;color:{{if and .AutoScale .AutoScale.Enabled}}#00b894{{else}}#777{{end}}">⚡ Auto-Scaling</span><form method="POST" action="/autoscale" style="margin:0"><input type="hidden" name="app" value="{{.App.Name}}">{{if and .AutoScale .AutoScale.Enabled}}<input type="hidden" name="enable" value="false"><button type="submit" style="background:#c0392b;color:#fff;border:none;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:.8em;font-weight:600">Disable</button>{{else}}<input type="hidden" name="enable" value="true"><button type="submit" style="background:#1a7a5a;color:#fff;border:none;padding:6px 14px;border-radius:5px;cursor:pointer;font-size:.8em;font-weight:600">Enable</button>{{end}}</form></div>{{if and .AutoScale .AutoScale.Enabled}}<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:6px;font-size:.7em"><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:#2c5f8a">{{printf "%.0f" .AutoScale.LastReqRate}}</div><div style="color:#999;margin-top:2px">Req/min</div></div><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:#b8700d">{{printf "%.1f" .AutoScale.ReqPerWorker}}</div><div style="color:#999;margin-top:2px">Req/Worker</div></div><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:#7b5ea7">{{.AutoScale.TargetWorkers}}</div><div style="color:#999;margin-top:2px">Target</div></div><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:#1a7a5a">{{.AutoScale.BusyWorkers}}/{{.AutoScale.IdleWorkers}}</div><div style="color:#999;margin-top:2px">Busy/Idle</div></div><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:{{if gt .AutoScale.CooldownSecs 0}}#f39c12{{else}}#00b894{{end}}">{{if gt .AutoScale.CooldownSecs 0}}{{.AutoScale.CooldownSecs}}s{{else}}Ready{{end}}</div><div style="color:#999;margin-top:2px">Cooldown</div></div><div style="background:#f5f3ef;padding:6px;border-radius:6px;text-align:center"><div style="font-size:1.2em;font-weight:bold;color:{{if .AutoScale.LastScaleDesc}}{{if eq .AutoScale.LastAction "scale_up"}}#27ae60{{else}}#e67e22{{end}}{{else}}#666{{end}}">{{if .AutoScale.LastScaleDesc}}{{.AutoScale.LastScaleDesc}}{{else}}None{{end}}</div><div style="color:#999;margin-top:2px">Last Scale</div></div></div><div style="font-size:.65em;color:#999;margin-top:6px;text-align:center">↑ &gt;8 req/worker • ↓ &lt;2 req/worker • 60s cooldown</div>{{else}}<div style="font-size:.8em;color:#999;text-align:center">Enable to auto-adjust workers based on request load</div>{{end}}</div><form method="POST" action="/worker-limits" style="display:flex;gap:8px;align-items:center;margin-top:8px;padding:8px;background:#f0ede8;border-radius:6px"><input type="hidden" name="app" value="{{.App.Name}}"><span style="font-size:.75em;color:#888">Limits:</span><label style="font-size:.7em;color:#999">Min<input type="number" name="min" value="{{.App.WorkerMin}}" min="1" max="20" style="width:45px;margin-left:4px;padding:4px;border:1px solid #d4cec4;border-radius:4px;background:#f5f3ef;color:#fff;font-size:.9em"></label><label style="font-size:.7em;color:#999">Max<input type="number" name="max" value="{{.App.WorkerMax}}" min="1" max="20" style="width:45px;margin-left:4px;padding:4px;border:1px solid #d4cec4;border-radius:4px;background:#f5f3ef;color:#fff;font-size:.9em"></label><button type="submit" style="padding:4px 10px;background:#3498db;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.75em">Save</button></form>{{end}}{{end}}{{if .App.Deps}}<div class="deps">{{range .App.Deps}}{{.}} • {{end}}</div>{{end}}<div class="actions"><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="start"><button class="btn btn-start" style="flex:1" {{if eq .Status "running"}}disabled{{end}}><span class="spinner"></span><span class="btn-text">{{if .App.IsSecurityDashboard}}Enable{{else}}Start{{end}}</span></button></form><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="stop"><button class="btn btn-stop" style="flex:1" {{if eq .Status "stopped"}}disabled{{end}}><span class="spinner"></span><span class="btn-text">{{if .App.IsSecurityDashboard}}Disable{{else}}Stop{{end}}</span></button></form><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="restart"><button class="btn btn-restart" style="flex:1"><span class="spinner"></span><span class="btn-text">Restart</span></button></form></div></div>{{end}}</div><script>document.querySelectorAll(".action-form").forEach(function(f){f.addEventListener("submit",function(e){var b=f.querySelector(".btn");if(b.disabled||b.classList.contains("loading")){e.preventDefault();return}b.classList.add("loading");document.querySelectorAll(".btn").forEach(function(x){if(!x.classList.contains("loading"))x.disabled=true})})})</script></body></html>`
	t := template.Must(template.New("index").Funcs(funcMap).Parse(tmpl))
	t.Execute(w, data)
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	appName := r.FormValue("app")
	action := r.FormValue("action")
	var app *App
	for _, a := range config.Apps { if a.Name == appName { app = &a; break } }
	if app == nil { http.Error(w, "App not found", http.StatusNotFound); return }
	mu.Lock()
	defer mu.Unlock()
	var cmd string
	switch action {
	case "start": cmd = app.StartCmd
	case "stop": cmd = app.StopCmd
	case "restart": cmd = app.StopCmd + " ; sleep 2 ; " + app.StartCmd
	case "add_worker":
		if app.WorkerAddCmd != "" {
			cmd = app.WorkerAddCmd
		} else if app.WorkerPidCmd != "" {
			pidOut, _ := runCmdTimeout(app.WorkerPidCmd, 2*time.Second)
			pids := strings.Split(strings.TrimSpace(pidOut), "\n")
			if len(pids) > 0 && pids[0] != "" { cmd = "kill -TTIN " + pids[0] }
		}
	case "remove_worker":
		if app.WorkerRemoveCmd != "" {
			cmd = app.WorkerRemoveCmd
		} else if app.WorkerPidCmd != "" {
			pidOut, _ := runCmdTimeout(app.WorkerPidCmd, 2*time.Second)
			pids := strings.Split(strings.TrimSpace(pidOut), "\n")
			if len(pids) > 0 && pids[0] != "" { cmd = "kill -TTOU " + pids[0] }
		}
	}
	if cmd != "" {
		output, err := runCmdTimeout(cmd, 30*time.Second)
		log.Printf("[%s] %s: %v - %s", appName, action, err, output)
	}
	time.Sleep(time.Second)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func killOrphanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	pidStr := r.FormValue("pid")
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 1 {
		http.Error(w, "Invalid PID", http.StatusBadRequest)
		return
	}

	// Safety: verify this PID is NOT systemd-managed before killing
	cgroup, _ := runCmdTimeout(fmt.Sprintf("cat /proc/%d/cgroup 2>/dev/null | head -1", pid), 2*time.Second)
	if strings.Contains(cgroup, "system.slice") || strings.Contains(cgroup, "init.scope") {
		log.Printf("[KillOrphan] BLOCKED: PID %d is systemd-managed (cgroup: %s)", pid, strings.TrimSpace(cgroup))
		http.Error(w, "Cannot kill systemd-managed process", http.StatusForbidden)
		return
	}

	// Get process name for logging
	name, _ := runCmdTimeout(fmt.Sprintf("ps -p %d -o comm= 2>/dev/null", pid), 2*time.Second)
	name = strings.TrimSpace(name)

	// SIGTERM first (graceful), then SIGKILL after 3s if still alive
	mu.Lock()
	defer mu.Unlock()
	runCmdTimeout(fmt.Sprintf("kill %d", pid), 2*time.Second)
	time.Sleep(3 * time.Second)
	// Check if still alive, force kill
	if _, err := runCmdTimeout(fmt.Sprintf("kill -0 %d", pid), 1*time.Second); err == nil {
		runCmdTimeout(fmt.Sprintf("kill -9 %d", pid), 2*time.Second)
		log.Printf("[KillOrphan] Force-killed PID %d (%s)", pid, name)
	} else {
		log.Printf("[KillOrphan] Killed PID %d (%s)", pid, name)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func autoScaleToggleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	appName := r.FormValue("app")
	enable := r.FormValue("enable") == "true"

	// Verify app exists and supports scaling
	var app *App
	for _, a := range config.Apps {
		if a.Name == appName {
			app = &a
			break
		}
	}
	if app == nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}
	if app.WorkerPidCmd == "" && app.WorkerAddCmd == "" {
		http.Error(w, "App does not support scaling", http.StatusBadRequest)
		return
	}

	setAutoScaleEnabled(appName, enable)
	log.Printf("[AutoScale] %s: auto-scaling %s", appName, map[bool]string{true: "enabled", false: "disabled"}[enable])
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// workerLimitsHandler updates worker min/max for an app
func workerLimitsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Redirect(w, r, "/", http.StatusSeeOther); return }
	appName := r.FormValue("app")
	minStr := r.FormValue("min")
	maxStr := r.FormValue("max")

	newMin, errMin := strconv.Atoi(minStr)
	newMax, errMax := strconv.Atoi(maxStr)
	if errMin != nil || errMax != nil || newMin < 1 || newMax < newMin {
		http.Error(w, "Invalid min/max values", http.StatusBadRequest)
		return
	}

	// Update config in memory and save to file
	mu.Lock()
	defer mu.Unlock()

	for i := range config.Apps {
		if config.Apps[i].Name == appName {
			config.Apps[i].WorkerMin = newMin
			config.Apps[i].WorkerMax = newMax
			break
		}
	}

	// Save to config file
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		http.Error(w, "Failed to serialize config", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		http.Error(w, "Failed to save config", http.StatusInternalServerError)
		return
	}

	log.Printf("[Config] %s: updated worker limits min=%d, max=%d", appName, newMin, newMax)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	if err := loadConfig(); err != nil { log.Fatalf("Failed to load config: %v", err) }

	// Log Slack configuration status
	if config.SlackEnabled && config.SlackWebhook != "" {
		log.Printf("[Slack] Alerts enabled")
	} else {
		log.Printf("[Slack] Alerts disabled")
	}

	// Initialize auto-scaling for apps with auto_scale_enabled in config
	for _, app := range config.Apps {
		if app.AutoScaleEnabled && (app.WorkerPidCmd != "" || app.WorkerAddCmd != "") {
			autoScaleStates[app.Name] = &AutoScaleState{Enabled: true}
			log.Printf("[AutoScale] %s: auto-scaling enabled on startup", app.Name)
		}
		// Log alert configuration
		if app.AlertWorkerMin > 0 || app.AlertWorkerMax > 0 {
			log.Printf("[Alert] %s: alerts configured (min: %d, max: %d)", app.Name, app.AlertWorkerMin, app.AlertWorkerMax)
		}
	}

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/", basicAuth(indexHandler))
	http.HandleFunc("/action", basicAuth(actionHandler))
	http.HandleFunc("/kill-orphan", basicAuth(killOrphanHandler))
	http.HandleFunc("/autoscale", basicAuth(autoScaleToggleHandler))
	http.HandleFunc("/worker-limits", basicAuth(workerLimitsHandler))
	addr := fmt.Sprintf(":%d", config.Port)
	log.Printf("Server Control starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
