package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

const (
	DnsSDBinary = "dns-sd"
	CaddyBinary = "caddy"
)

type Config struct {
	ip         string
	configFile string
}

func parseFlags() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ip, "ip", "", "IP address to advertise (required)")
	flag.StringVar(&cfg.configFile, "config", ".localhttps.yaml", "the path to the config file")
	flag.Parse()

	if cfg.ip == "" {
		return nil, fmt.Errorf("ip address is required")
	}

	if cfg.configFile == "" {
		return nil, fmt.Errorf("config file is required")
	}

	// Validate IP address
	if ip := net.ParseIP(cfg.ip); ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", cfg.ip)
	}

	return cfg, nil
}

func buildCaddyReverseProxy(domain, addr string) string {
	return fmt.Sprintf(`
%s {
	bind 0.0.0.0
    tls internal
    reverse_proxy %s
}
`, domain, addr)
}

type ManagedProcess struct {
	cmd      *exec.Cmd
	logFile  *os.File
	done     chan error
	stopOnce sync.Once
	name     string
}

func NewManagedProcess(logName, name string, args ...string) (*ManagedProcess, error) {
	logPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d.log", logName, os.Getpid()))
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, fmt.Errorf("create log file: %w", err)
	}

	fmt.Printf("Logs for %s being written to: %s\n", name, logPath)

	cmd := exec.Command(name, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Create process group for better control
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	return &ManagedProcess{
		cmd:     cmd,
		logFile: logFile,
		done:    make(chan error, 1),
		name:    name,
	}, nil
}

func (p *ManagedProcess) Start() error {
	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}

	go func() {
		p.done <- p.cmd.Wait()
	}()

	return nil
}

func (p *ManagedProcess) Stop() error {
	var stopErr error
	p.stopOnce.Do(func() {
		defer p.logFile.Close()

		if p.cmd.Process == nil {
			return
		}

		// Send SIGTERM first
		stopErr = p.cmd.Process.Signal(syscall.SIGTERM)
		if stopErr != nil {
			return
		}

		// Wait for process to exit with timeout
		select {
		case <-p.done:
			return
		case <-time.After(3 * time.Second):
			// If SIGTERM doesn't work, use SIGKILL
			pgid, err := syscall.Getpgid(p.cmd.Process.Pid)
			if err == nil {
				syscall.Kill(-pgid, syscall.SIGKILL) // Negative pgid kills the whole process group
			} else {
				p.cmd.Process.Kill()
			}
			<-p.done // Wait for the process to be fully killed
		}
	})
	return stopErr
}

// [Previous parseFlags, buildCaddyReverseProxy functions remain the same]

func startCaddy(caddyfile string) (*ManagedProcess, error) {
	// Write caddyfile to temporary file
	tmpFile, err := os.CreateTemp("", "Caddyfile")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	if _, err := tmpFile.WriteString(caddyfile); err != nil {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("write caddyfile: %w", err)
	}
	tmpFile.Close()

	// Start Caddy with the config file
	proc, err := NewManagedProcess(CaddyBinary, CaddyBinary, "run", "--config", tmpFile.Name())
	if err != nil {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("create caddy process: %w", err)
	}

	if err := proc.Start(); err != nil {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("start caddy: %w", err)
	}

	// Clean up temp file when process exits
	go func() {
		<-proc.done
		os.Remove(tmpFile.Name())
	}()

	return proc, nil
}

func startDNSSD(domain, ip string) (*ManagedProcess, error) {
	proc, err := NewManagedProcess(fmt.Sprintf("%s-%s", DnsSDBinary, domain), DnsSDBinary, "-P", domain, "_http._tcp", "local", "443", domain, ip)
	if err != nil {
		return nil, fmt.Errorf("create dns-sd process: %w", err)
	}

	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start dns-sd: %w", err)
	}

	return proc, nil
}

func main() {
	// Parse command line flags
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	k := koanf.New(".")
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	log.Info("loaded config", "ip", cfg.ip, "config_file", cfg.configFile)

	if err := k.Load(file.Provider(cfg.configFile), yaml.Parser()); err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	flatMap := k.All()

	// Build Caddyfile
	caddyfile := strings.Builder{}
	for domain, addrInterface := range flatMap {
		addr, ok := addrInterface.(string)
		if !ok {
			log.Warn("invalid address type", "addr", addrInterface)
			continue
		}
		log.Info("found domain-address pair", "domain", domain, "address", addr, "url", fmt.Sprintf("https://%s", domain))
		caddyfile.WriteString(buildCaddyReverseProxy(domain, addr))
	}

	// Start Caddy
	caddyProc, err := startCaddy(caddyfile.String())
	if err != nil {
		log.Error("failed to start caddy", "err", err)
		os.Exit(1)
	}

	// Start DNS-SD for each domain
	var dnsProcesses []*ManagedProcess
	for domain := range flatMap {
		dnsProc, err := startDNSSD(domain, cfg.ip)
		if err != nil {
			log.Error("failed to start dns-sd", "domain", domain, "err", err)
			continue
		}
		dnsProcesses = append(dnsProcesses, dnsProc)
	}

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// Cleanup with timeout
	log.Info("shutting down...")

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create error channel for shutdown errors
	shutdownErrs := make(chan error, 1+len(dnsProcesses))

	// Stop all processes concurrently
	var wg sync.WaitGroup

	// Stop Caddy
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := caddyProc.Stop(); err != nil {
			log.Error("failed to stop caddy", "err", err)
			shutdownErrs <- fmt.Errorf("caddy: %w", err)
		}
	}()

	// Stop all DNS-SD processes
	for _, dnsProc := range dnsProcesses {
		wg.Add(1)
		go func(proc *ManagedProcess) {
			defer wg.Done()
			if err := proc.Stop(); err != nil {
				log.Error("failed to stop dns-sd", "err", err)
				shutdownErrs <- fmt.Errorf("dns-sd: %w", err)
			}
		}(dnsProc)
	}

	// Wait for all processes to stop or timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		log.Error("shutdown timed out")
	case <-done:
		log.Info("all processes stopped successfully")
	}

	// Check for any shutdown errors
	close(shutdownErrs)
	var errors []error
	for err := range shutdownErrs {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		log.Error("errors during shutdown", "count", len(errors))
		os.Exit(1)
	}
}
