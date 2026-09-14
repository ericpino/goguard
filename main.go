// goGuard - Real-time Host Threat Detection & Prevention Daemon
// Author: Eric Pino

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/hpcloud/tail"
	"github.com/joho/godotenv"
)

type DaemonStatus struct {
	PID          int               `json:"pid"`
	StartTime    time.Time         `json:"start_time"`
	LogFiles     []string          `json:"log_files"`
	LogFilePath  string            `json:"log_file_path"`
	BlockMode    string            `json:"block_mode"`
	MaxHits      int               `json:"max_hits"`
	WindowSecs   int               `json:"window_secs"`
	Whitelist    []string          `json:"whitelist"`
	TotalLines   uint64            `json:"total_lines"`
	TotalThreats uint64            `json:"total_threats"`
	BlockedIPs   map[string]string `json:"blocked_ips"`
}

var defaultCloudflareIPs = []string{
	// Cloudflare IPv4 Ranges
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// Cloudflare IPv6 Ranges
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var (
	globalStatus         DaemonStatus
	statusMutex          sync.Mutex
	statusFilePath       = filepath.Join(os.TempDir(), "goguard.status.json")
	totalLinesProcessed  uint64
	totalThreatsDetected uint64
)

func saveStatus() {
	statusMutex.Lock()
	defer statusMutex.Unlock()

	globalStatus.TotalLines = atomic.LoadUint64(&totalLinesProcessed)
	globalStatus.TotalThreats = atomic.LoadUint64(&totalThreatsDetected)

	data, err := json.MarshalIndent(globalStatus, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(statusFilePath, data, 0644)
}

func printStatusAndExit() {
	_ = godotenv.Load()
	data, err := os.ReadFile(statusFilePath)
	if err != nil {
		fmt.Println("goGuard daemon is NOT running (no active status file found).")
		os.Exit(1)
	}

	var status DaemonStatus
	if err := json.Unmarshal(data, &status); err != nil {
		fmt.Printf("Failed to parse status file: %v\n", err)
		os.Exit(1)
	}

	// Check if PID is alive
	isRunning := false
	if process, err := os.FindProcess(status.PID); err == nil {
		if err := process.Signal(syscall.Signal(0)); err == nil {
			isRunning = true
		}
	}

	statusStr := "RUNNING"
	if !isRunning {
		statusStr = "STOPPED  (Stale state)"
	}

	uptime := time.Since(status.StartTime).Round(time.Second)

	fmt.Println("==================================================")
	fmt.Println("  goGuard Status Report")
	fmt.Println("==================================================")
	fmt.Printf(" Status:           %s (PID: %d)\n", statusStr, status.PID)
	fmt.Printf(" Uptime:           %s\n", uptime)
	if len(status.LogFiles) > 1 {
		fmt.Printf(" Log Files Tailed: (%d files)\n", len(status.LogFiles))
		for _, f := range status.LogFiles {
			fmt.Printf("   - %s\n", f)
		}
	} else if len(status.LogFiles) == 1 {
		fmt.Printf(" Log File Tailed:  %s\n", status.LogFiles[0])
	} else if status.LogFilePath != "" {
		fmt.Printf(" Log File Tailed:  %s\n", status.LogFilePath)
	}
	fmt.Printf(" Blocking Mode:    %s\n", status.BlockMode)
	fmt.Printf(" Max Hits Window:  %d hits / %ds\n", status.MaxHits, status.WindowSecs)
	fmt.Printf(" Whitelisted IPs:  %s\n", strings.Join(status.Whitelist, ", "))
	fmt.Println()
	fmt.Println(" Threat Metrics:")
	fmt.Println(" --------------------------------------------------")
	fmt.Printf(" Total Log Lines Processed:  %d\n", status.TotalLines)
	fmt.Printf(" Total Threats Detected:     %d\n", status.TotalThreats)
	fmt.Printf(" Total IPs Banned:           %d\n", len(status.BlockedIPs))
	fmt.Println()
	fmt.Println(" Currently Blocked IPs:")
	fmt.Println(" --------------------------------------------------")
	if len(status.BlockedIPs) == 0 {
		fmt.Println("  (No IPs currently blocked)")
	} else {
		for ip, t := range status.BlockedIPs {
			fmt.Printf("  %-18s (Blocked at %s)\n", ip, t)
		}
	}
	fmt.Println("==================================================")
	os.Exit(0)
}

type ThreatTracker struct {
	mu         sync.Mutex
	hits       map[string][]time.Time
	maxHits    int
	windowSecs time.Duration
}

func NewThreatTracker(maxHits int, windowSecs time.Duration) *ThreatTracker {
	tt := &ThreatTracker{
		hits:       make(map[string][]time.Time),
		maxHits:    maxHits,
		windowSecs: windowSecs,
	}

	// Periodic cleanup routine for stale IP tracking entries
	go func() {
		for {
			time.Sleep(1 * time.Minute)
			tt.mu.Lock()
			now := time.Now()
			for ip, timestamps := range tt.hits {
				var valid []time.Time
				for _, t := range timestamps {
					if now.Sub(t) <= tt.windowSecs {
						valid = append(valid, t)
					}
				}
				if len(valid) == 0 {
					delete(tt.hits, ip)
				} else {
					tt.hits[ip] = valid
				}
			}
			tt.mu.Unlock()
		}
	}()

	return tt
}

func (tt *ThreatTracker) RecordHit(ip string) (int, bool) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	now := time.Now()
	timestamps := tt.hits[ip]
	var valid []time.Time
	for _, t := range timestamps {
		if now.Sub(t) <= tt.windowSecs {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	tt.hits[ip] = valid
	hitCount := len(valid)
	shouldBlock := hitCount >= tt.maxHits
	return hitCount, shouldBlock
}

func isWhitelisted(ip string, whitelist []string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	for _, entry := range whitelist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if entry == ip {
			return true
		}

		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			if ipNet.Contains(clientIP) {
				return true
			}
		}
	}

	return false
}

func resolveLogFiles(rawConfig string) []string {
	var files []string
	seen := make(map[string]bool)

	parts := strings.Split(rawConfig, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		matches, err := filepath.Glob(part)
		if err != nil || len(matches) == 0 {
			// If glob matched nothing, keep the raw path so tail will follow or wait for creation
			if !seen[part] {
				seen[part] = true
				files = append(files, part)
			}
			continue
		}

		for _, match := range matches {
			if fi, err := os.Stat(match); err == nil && fi.IsDir() {
				continue
			}
			if !seen[match] {
				seen[match] = true
				files = append(files, match)
			}
		}
	}

	return files
}

type logEntry struct {
	filePath string
	line     string
}

func main() {
	statusFlag := flag.Bool("status", false, "Display current goGuard threat detection status and exit")
	flag.Parse()

	if *statusFlag {
		printStatusAndExit()
	}

	_ = godotenv.Load()

	logFilePathRaw := getEnv("LOG_FILE_PATH", "/var/log/nginx/access.log")
	logFiles := resolveLogFiles(logFilePathRaw)
	if len(logFiles) == 0 {
		log.Fatalf("No log files configured or found for path/pattern: %s", logFilePathRaw)
	}

	botKeys := getEnv("TELEGRAM_BOT_KEY", "KEYS")
	zoneID := getEnv("CLOUDFLARE_ZONE_ID", "ZONE_ID")
	cfApiKey := getEnv("CLOUDFLARE_API_KEY", "KEY")
	cfApiEndpoint := getEnv("CLOUDFLARE_API_ENDPOINT", "https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules")
	chatIDStr := getEnv("TELEGRAM_CHAT_ID", "ID")

	maxHits, _ := strconv.Atoi(getEnv("MAX_HITS", "3"))
	if maxHits <= 0 {
		maxHits = 3
	}

	windowSecsInt, _ := strconv.Atoi(getEnv("TIME_WINDOW_SECONDS", "60"))
	if windowSecsInt <= 0 {
		windowSecsInt = 60
	}
	windowDuration := time.Duration(windowSecsInt) * time.Second

	whitelistRaw := getEnv("WHITELIST_IPS", "127.0.0.1,::1")
	whitelist := strings.Split(whitelistRaw, ",")

	whitelistCloudflare := strings.ToLower(getEnv("WHITELIST_CLOUDFLARE", "true"))
	if whitelistCloudflare == "true" || whitelistCloudflare == "1" || whitelistCloudflare == "yes" {
		whitelist = append(whitelist, defaultCloudflareIPs...)
	}

	chatID, err := strconv.ParseInt(chatIDStr, 10, 64)
	if err != nil && chatIDStr != "ID" {
		log.Fatal("Invalid TELEGRAM_CHAT_ID:", err)
	}

	blockMode := strings.ToLower(getEnv("BLOCK_MODE", "both"))
	enableCloudflare := blockMode == "cloudflare" || blockMode == "both"
	enableIPTables := blockMode == "iptables" || blockMode == "both"

	bot, err := tgbotapi.NewBotAPI(botKeys)
	if err != nil {
		log.Printf("Warning: Could not initialize Telegram Bot (%v). Alerts will be logged to console.", err)
	}

	// Initialize global daemon status tracking
	globalStatus = DaemonStatus{
		PID:         os.Getpid(),
		StartTime:   time.Now(),
		LogFiles:    logFiles,
		LogFilePath: logFilePathRaw,
		BlockMode:   blockMode,
		MaxHits:     maxHits,
		WindowSecs:  windowSecsInt,
		Whitelist:   whitelist,
		BlockedIPs:  make(map[string]string),
	}
	saveStatus()

	// Periodically update status file
	go func() {
		for {
			time.Sleep(10 * time.Second)
			saveStatus()
		}
	}()

	tracker := NewThreatTracker(maxHits, windowDuration)

	// Refined attack patterns
	attackPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+all\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|update\s+.*\s+set|information_schema|benchmark\s*\(|sleep\s*\()`),
		regexp.MustCompile(`(?i)('|"|%27|%22)\s*(or|and)\s*('|"|%27|%22|[0-9]=[0-9]|true|false)`),
		regexp.MustCompile(`(?i)(<\s*script[^>]*>|javascript\s*:|vbscript\s*:|data\s*:\s*text/html|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=)`),
		regexp.MustCompile(`(?i)(<|\%3C)\s*(img|iframe|body|svg|input|link|object|embed)\b[^>]*(src|href|data|onload|onerror)\s*=`),
		regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c)`),
		regexp.MustCompile(`(?i)(/etc/passwd|/etc/shadow|/etc/issue|/proc/self/environ|c:\\boot\.ini|c:\\windows\\win\.ini)`),
		regexp.MustCompile(`(?i)(\.env|\.git/config|\.svn/entries|wp-config\.php|config\.json|docker-compose\.yml)`),
		regexp.MustCompile(`(?i)(;|\||&&|\$\(|\x60)\s*(wget|curl|nc|netcat|ncat|bash|sh|zsh|powershell|cmd\.exe|python|perl|ruby|php)\b`),
		regexp.MustCompile(`(?i)(eval\(|system\(|passthru\(|shell_exec\(|exec\(|popen\(|proc_open\()`),
		regexp.MustCompile(`(?i)(\$\{\s*jndi\s*:|\{\{\s*.*\s*\}\}|\$\{.*exec.*\}|<%=\s*.*\s*%>)`),
		regexp.MustCompile(`(?i)(/phpmyadmin|/wp-admin|/wp-login\.php|/xmlrpc\.php|/\.well-known/security\.txt)`),
	}

	linesChan := make(chan logEntry, 2048)

	for _, file := range logFiles {
		go func(targetFile string) {
			tailConfig := tail.Config{
				Location: &tail.SeekInfo{Offset: 0, Whence: os.SEEK_END},
				ReOpen:   true,
				Follow:   true,
				Logger:   tail.DiscardingLogger,
			}
			tailFile, err := tail.TailFile(targetFile, tailConfig)
			if err != nil {
				log.Printf("Failed to tail log file %s: %v", targetFile, err)
				return
			}
			log.Printf("Tailing log file: %s", targetFile)

			for line := range tailFile.Lines {
				if line.Err != nil {
					continue
				}
				linesChan <- logEntry{filePath: targetFile, line: line.Text}
			}
		}(file)
	}

	log.Printf("Threat detection daemon started (PID: %d). Monitoring %d log target(s) (Block mode: %s, Max Hits: %d/%ds)",
		os.Getpid(), len(logFiles), blockMode, maxHits, windowSecsInt)

	// Process log entries and send alerts in real-time.
	for entry := range linesChan {
		atomic.AddUint64(&totalLinesProcessed, 1)

		fields := strings.Fields(entry.line)
		if len(fields) < 7 {
			continue
		}

		clientIP := fields[0]
		url := fields[6]

		if net.ParseIP(clientIP) == nil {
			continue
		}

		if isWhitelisted(clientIP, whitelist) {
			continue
		}

		for _, pattern := range attackPatterns {
			if pattern.MatchString(url) {
				atomic.AddUint64(&totalThreatsDetected, 1)
				hitCount, shouldBlock := tracker.RecordHit(clientIP)
				
				sourcePrefix := ""
				if len(logFiles) > 1 {
					sourcePrefix = fmt.Sprintf("[%s] ", filepath.Base(entry.filePath))
				}

				message := fmt.Sprintf("%sThreat Detected from IP %s (Hit %d/%d) - URL: %s", sourcePrefix, clientIP, hitCount, maxHits, url)
				log.Println(message)

				if bot != nil {
					sendTelegramAlert(bot, chatID, message)
				}

				if shouldBlock {
					log.Printf("Blocking IP %s after reaching threshold of %d hits within %ds window.", clientIP, maxHits, windowSecsInt)

					statusMutex.Lock()
					globalStatus.BlockedIPs[clientIP] = time.Now().Format("2006-01-02 15:04:05")
					statusMutex.Unlock()
					saveStatus()

					blockIP(clientIP, zoneID, cfApiKey, cfApiEndpoint, enableCloudflare, enableIPTables)
				}

				break
			}
		}
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func blockIP(ip, zoneID, apiKey, endpointTemplate string, enableCloudflare, enableIPTables bool) {
	if enableCloudflare && zoneID != "" && zoneID != "ZONE_ID" && apiKey != "" && apiKey != "KEY" {
		blockIPUsingCloudflareHTTP(zoneID, ip, apiKey, endpointTemplate)
	}

	if enableIPTables {
		blockIPUsingIPTables(ip)
	}
}

func blockIPUsingIPTables(ip string) {
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if err := checkCmd.Run(); err == nil {
		log.Printf("[iptables] IP %s is already blocked in firewall.", ip)
		return
	}

	addCmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	output, err := addCmd.CombinedOutput()
	if err != nil {
		log.Printf("[iptables] Failed to block IP %s: %v (Output: %s). Make sure to run with root/sudo privileges.", ip, err, string(output))
		return
	}

	log.Printf("[iptables] Successfully blocked IP %s", ip)
}

func sendTelegramAlert(bot *tgbotapi.BotAPI, chatID int64, message string) {
	msg := tgbotapi.NewMessage(chatID, message)
	_, err := bot.Send(msg)
	if err != nil {
		log.Printf("Failed to send Telegram alert: %v", err)
	}
}

func blockIPUsingCloudflareHTTP(zoneID, ip, apiKey, endpointTemplate string) {
	var endpoint string
	if strings.Contains(endpointTemplate, "%s") {
		endpoint = fmt.Sprintf(endpointTemplate, zoneID)
	} else {
		endpoint = endpointTemplate
	}

	payload := []byte(`{
		"configuration": {
			"target": "ip",
			"value": "` + ip + `"
		},
		"mode": "block",
		"notes": "Blocked by threat detection daemon"
	}`)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(payload))
	if err != nil {
		log.Printf("[Cloudflare] Failed to create HTTP request: %v", err)
		return
	}

	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[Cloudflare] Failed to send HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("[Cloudflare] Failed to block IP %s: HTTP status code %d", ip, resp.StatusCode)
		return
	}

	log.Printf("[Cloudflare] Successfully blocked IP %s", ip)
}
