package main

import (
	"bufio"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type App struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	WorkDir        string   `json:"workdir"`
	StartCmd       string   `json:"start_cmd"`
	StopCmd        string   `json:"stop_cmd"`
	StatusCmd      string   `json:"status_cmd"`
	ProcMatch      string   `json:"proc_match"`
	Deps           []string `json:"deps"`
	MetricsCmd     string   `json:"metrics_cmd"`
	WorkerPidCmd   string   `json:"worker_pid_cmd"`
	WorkerMin      int      `json:"worker_min"`
	WorkerMax      int      `json:"worker_max"`
}

type Config struct {
	Password string `json:"password"`
	Port     int    `json:"port"`
	Apps     []App  `json:"apps"`
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

type AppStatus struct {
	App          App
	Status       string
	CPUPercent   float64
	MemMB        float64
	ProcCount    int
	Metrics      []AppMetric
	WorkerCount  int
	CanScale     bool
}

var (
	config     Config
	configFile = "/opt/server-control/config.json"
	mu         sync.Mutex
	prevIdle   uint64
	prevTotal  uint64
)

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}
	// Load drop-in app configs from apps.d/*.json
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

func getProcessStats(procMatch string) (int, float64, float64) {
	if procMatch == "" { return 0, 0, 0 }
	out, err := runCmdTimeout("pgrep -f '"+procMatch+"'", 2*time.Second)
	if err != nil { return 0, 0, 0 }
	pids := strings.Split(strings.TrimSpace(out), "\n")
	count := 0
	var totalCPU, totalMemPct float64
	for _, pidStr := range pids {
		if pidStr == "" { continue }
		count++
		psOut, _ := runCmdTimeout("ps -p "+pidStr+" -o %cpu,%mem --no-headers 2>/dev/null", time.Second)
		fields := strings.Fields(psOut)
		if len(fields) >= 2 {
			cpu, _ := strconv.ParseFloat(fields[0], 64)
			mem, _ := strconv.ParseFloat(fields[1], 64)
			totalCPU += cpu
			totalMemPct += mem
		}
	}
	var memMB float64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var memTotal uint64
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "MemTotal:") {
				fmt.Sscanf(scanner.Text(), "MemTotal: %d kB", &memTotal)
				break
			}
		}
		memMB = totalMemPct / 100 * float64(memTotal) / 1024
	}
	return count, totalCPU, memMB
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

func getReqPerMin(metrics []AppMetric) int {
	for _, m := range metrics {
		// Check activity-related labels (priority order: 1h metrics first)
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
			// Parse as float to handle "8.2K" -> 8.2 * 1000
			num, err := strconv.ParseFloat(val, 64)
			if err != nil {
				continue
			}
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
	if count > 0 { count-- }
	return count
}

func getAppStatus(app App) AppStatus {
	status := AppStatus{App: app, Status: "stopped", CanScale: app.WorkerPidCmd != ""}
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
	if app.MetricsCmd != "" { status.Metrics = getAppMetrics(app.MetricsCmd) }
	if app.WorkerPidCmd != "" { status.WorkerCount = getWorkerCount(app.ProcMatch) }
	return status
}

func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err == nil && cookie.Value == "authenticated" { next(w, r); return }
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(config.Password)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "authenticated", Path: "/", MaxAge: 86400 * 7, HttpOnly: true})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	fmt.Fprint(w, `<!DOCTYPE html><html><head><title>Login</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#eee;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;padding:20px}.login-box{background:#16213e;padding:40px;border-radius:12px;width:100%;max-width:360px}h1{margin:0 0 25px;color:#74b9ff;font-size:1.5em;text-align:center}input{padding:14px;width:100%;border:none;border-radius:8px;margin-bottom:15px;font-size:16px;background:#0d1b2a;color:#fff}button{padding:14px;width:100%;background:#e94560;color:white;border:none;border-radius:8px;cursor:pointer;font-size:16px;font-weight:600}</style></head><body><div class="login-box"><h1>Server Control</h1><form method="POST"><input type="password" name="password" placeholder="Password" autofocus><button type="submit">Login</button></form></div></body></html>`)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	metrics := getSystemMetrics()
	var apps []AppStatus
	for _, app := range config.Apps { apps = append(apps, getAppStatus(app)) }
	sort.Slice(apps, func(i, j int) bool {
		return getReqPerMin(apps[i].Metrics) > getReqPerMin(apps[j].Metrics)
	})
	data := struct { Metrics SystemMetrics; Apps []AppStatus }{metrics, apps}
	tmpl := `<!DOCTYPE html><html><head><title>Server Control</title><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><style>*{box-sizing:border-box}body{font-family:-apple-system,sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:15px}h1{color:#e94560;font-size:1.4em;margin:0 0 15px}.header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:15px}.header-links a{color:#74b9ff;text-decoration:none;margin-left:15px;font-size:.9em}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}.metric{background:#16213e;padding:15px;border-radius:10px;text-align:center}.metric-value{font-size:1.8em;font-weight:bold}.metric-label{font-size:.75em;color:#888;margin-top:5px}.metric-sub{font-size:.7em;color:#666}.green{color:#00b894}.yellow{color:#fdcb6e}.red{color:#e74c3c}.apps{display:grid;gap:12px}.app{background:#16213e;padding:15px;border-radius:10px}.app-header{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:10px}.app-name{font-size:1.1em;font-weight:600;color:#74b9ff;flex:1}.status{padding:4px 12px;border-radius:15px;font-size:.75em;font-weight:600}.status.running{background:#00b894}.status.stopped{background:#d63031}.app-desc{color:#a0a0a0;font-size:.85em;margin-bottom:10px}.app-stats{display:flex;gap:10px;font-size:.8em;color:#888;margin-bottom:12px;flex-wrap:wrap}.app-stats span{background:#0d1b2a;padding:4px 10px;border-radius:5px}.app-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(90px,1fr));gap:8px;margin-bottom:12px}.app-metric{background:#0d1b2a;padding:10px 8px;border-radius:8px;text-align:center}.app-metric-value{font-size:1.3em;font-weight:bold;color:#fff}.app-metric-label{font-size:.65em;color:#888;margin-top:3px}.worker-control{display:flex;align-items:center;gap:8px;background:#0d1b2a;padding:8px 12px;border-radius:8px;margin-bottom:12px}.worker-control span{font-size:.85em;color:#9b59b6}.worker-btn{width:28px;height:28px;border:none;border-radius:6px;cursor:pointer;font-size:1.1em;font-weight:bold;display:flex;align-items:center;justify-content:center}.worker-btn.add{background:#27ae60;color:white}.worker-btn.remove{background:#e74c3c;color:white}.worker-btn:disabled{opacity:.3;cursor:not-allowed}.worker-count{font-size:1.2em;font-weight:bold;color:#9b59b6;min-width:20px;text-align:center}.deps{font-size:.75em;color:#636e72;margin-bottom:12px}.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{padding:10px 18px;border:none;border-radius:6px;cursor:pointer;font-size:.85em;font-weight:600;flex:1;min-width:80px;display:flex;align-items:center;justify-content:center;gap:8px}.btn-start{background:#00b894;color:white}.btn-stop{background:#d63031;color:white}.btn-restart{background:#fdcb6e;color:#333}.btn:disabled{opacity:.4;cursor:not-allowed}.btn.loading{opacity:.7;cursor:wait}.spinner{width:14px;height:14px;border:2px solid transparent;border-top-color:currentColor;border-radius:50%;animation:spin .8s linear infinite;display:none}.btn.loading .spinner{display:inline-block}.btn.loading .btn-text{display:none}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:480px){body{padding:10px}.metric-value{font-size:1.5em}.btn{padding:12px 10px}.app-metrics{grid-template-columns:repeat(3,1fr)}}</style></head><body><div class="header"><h1>Server Control</h1><div class="header-links"><a href="/">Refresh</a> <a href="/logout">Logout</a></div></div><div class="metrics"><div class="metric"><div class="metric-value {{if lt .Metrics.CPUPercent 50.0}}green{{else if lt .Metrics.CPUPercent 80.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.CPUPercent}}%</div><div class="metric-label">CPU</div><div class="metric-sub">Load: {{.Metrics.LoadAvg}}</div></div><div class="metric"><div class="metric-value {{if lt .Metrics.MemPercent 70.0}}green{{else if lt .Metrics.MemPercent 90.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.MemPercent}}%</div><div class="metric-label">RAM</div><div class="metric-sub">{{printf "%.1f" .Metrics.MemUsedGB}}/{{printf "%.1f" .Metrics.MemTotalGB}} GB</div></div><div class="metric"><div class="metric-value {{if lt .Metrics.DiskPercent 70.0}}green{{else if lt .Metrics.DiskPercent 90.0}}yellow{{else}}red{{end}}">{{printf "%.0f" .Metrics.DiskPercent}}%</div><div class="metric-label">Disk</div><div class="metric-sub">{{printf "%.0f" .Metrics.DiskUsedGB}}/{{printf "%.0f" .Metrics.DiskTotalGB}} GB</div></div><div class="metric"><div class="metric-value green">{{.Metrics.Uptime}}</div><div class="metric-label">Uptime</div></div></div><div class="apps">{{range .Apps}}<div class="app"><div class="app-header"><span class="app-name">{{.App.Name}}</span><span class="status {{.Status}}">{{.Status}}</span></div><div class="app-desc">{{.App.Description}}</div>{{if or (gt .ProcCount 0) (gt .MemMB 0.0)}}<div class="app-stats">{{if gt .CPUPercent 0.0}}<span>CPU: {{printf "%.1f" .CPUPercent}}%</span>{{end}}{{if gt .MemMB 0.0}}<span>RAM: {{printf "%.0f" .MemMB}} MB</span>{{end}}{{if gt .ProcCount 0}}<span>Procs: {{.ProcCount}}</span>{{end}}</div>{{end}}{{if .Metrics}}<div class="app-metrics">{{range .Metrics}}<div class="app-metric"><div class="app-metric-value" {{if .Color}}style="color: {{.Color}}"{{end}}>{{.Value}}</div><div class="app-metric-label">{{.Label}}</div></div>{{end}}</div>{{end}}{{if .CanScale}}<div class="worker-control"><span>Workers:</span><form method="POST" action="/action" style="display:inline"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="remove_worker"><button type="submit" class="worker-btn remove" {{if le .WorkerCount .App.WorkerMin}}disabled{{end}} title="Remove worker (min: {{.App.WorkerMin}})">−</button></form><span class="worker-count">{{.WorkerCount}}</span><form method="POST" action="/action" style="display:inline"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="add_worker"><button type="submit" class="worker-btn add" {{if ge .WorkerCount .App.WorkerMax}}disabled{{end}} title="Add worker (max: {{.App.WorkerMax}})">+</button></form><span style="font-size:.65em;color:#555;margin-left:auto">~10 req/min per worker • max {{.App.WorkerMax}}</span></div>{{end}}{{if .App.Deps}}<div class="deps">{{range .App.Deps}}{{.}} • {{end}}</div>{{end}}<div class="actions"><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="start"><button class="btn btn-start" style="flex:1" {{if eq .Status "running"}}disabled{{end}}><span class="spinner"></span><span class="btn-text">Start</span></button></form><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="stop"><button class="btn btn-stop" style="flex:1" {{if eq .Status "stopped"}}disabled{{end}}><span class="spinner"></span><span class="btn-text">Stop</span></button></form><form method="POST" action="/action" class="action-form" style="flex:1;display:flex"><input type="hidden" name="app" value="{{.App.Name}}"><input type="hidden" name="action" value="restart"><button class="btn btn-restart" style="flex:1"><span class="spinner"></span><span class="btn-text">Restart</span></button></form></div></div>{{end}}</div><script>document.querySelectorAll(".action-form").forEach(function(f){f.addEventListener("submit",function(e){var b=f.querySelector(".btn");if(b.disabled||b.classList.contains("loading")){e.preventDefault();return}b.classList.add("loading");document.querySelectorAll(".btn").forEach(function(x){if(!x.classList.contains("loading"))x.disabled=true})})})</script></body></html>`
	t := template.Must(template.New("index").Parse(tmpl))
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
		if app.WorkerPidCmd != "" {
			pidOut, _ := runCmdTimeout(app.WorkerPidCmd, 2*time.Second)
			pids := strings.Split(strings.TrimSpace(pidOut), "\n")
			if len(pids) > 0 && pids[0] != "" { cmd = "kill -TTIN " + pids[0] }
		}
	case "remove_worker":
		if app.WorkerPidCmd != "" {
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

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func main() {
	if err := loadConfig(); err != nil { log.Fatalf("Failed to load config: %v", err) }
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/", basicAuth(indexHandler))
	http.HandleFunc("/action", basicAuth(actionHandler))
	addr := fmt.Sprintf(":%d", config.Port)
	log.Printf("Server Control starting on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
