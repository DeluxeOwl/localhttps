package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/go-cmd/cmd"
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
    tls internal
    reverse_proxy %s
}
`, domain, addr)
}

func startCaddy(caddyfile string, log *slog.Logger) *cmd.Cmd {
	// Write caddyfile to temporary file
	tmpFile, err := os.CreateTemp("", "Caddyfile")
	if err != nil {
		log.Error("create temp file", "err", err)
		return nil
	}

	if _, err := tmpFile.WriteString(caddyfile); err != nil {
		log.Error("write caddyfile", "err", err)
		return nil
	}

	if err := tmpFile.Close(); err != nil {
		log.Error("close temp file", "err", err)
		return nil
	}

	// Start Caddy with the config file
	caddyCmd := cmd.NewCmd(CaddyBinary, "run", "--config", tmpFile.Name())
	statusChan := caddyCmd.Start()

	// Monitor Caddy status
	go func() {
		finalStatus := <-statusChan
		if finalStatus.Error != nil {
			log.Error("caddy process ended with error", "err", finalStatus.Error)
		}
		// Clean up temp file
		os.Remove(tmpFile.Name())
	}()

	return caddyCmd
}

func startDNSSD(domain, ip string, log *slog.Logger) *cmd.Cmd {
	dnsCmd := cmd.NewCmd(DnsSDBinary, "-P", domain, "_http._tcp", "local", "443", domain, ip)
	statusChan := dnsCmd.Start()

	// Monitor DNS-SD status
	go func() {
		finalStatus := <-statusChan
		if finalStatus.Error != nil {
			log.Error("dns-sd process ended with error",
				"domain", domain,
				"err", finalStatus.Error)
		}
	}()

	return dnsCmd
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

	if err := k.Load(file.Provider(".localhttps.yaml"), yaml.Parser()); err != nil {
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
		log.Info("found domain-address pair", "domain", domain, "address", addr)
		caddyfile.WriteString(buildCaddyReverseProxy(domain, addr))
	}

	// Start Caddy
	caddyCmd := startCaddy(caddyfile.String(), log)
	if caddyCmd == nil {
		log.Error("failed to start caddy")
		os.Exit(1)
	}

	// Start DNS-SD for each domain
	var dnsCommands []*cmd.Cmd
	for domain := range flatMap {
		dnsCmd := startDNSSD(domain, cfg.ip, log)
		dnsCommands = append(dnsCommands, dnsCmd)
	}

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// Cleanup
	log.Info("shutting down...")

	// Stop Caddy
	err = caddyCmd.Stop()
	if err != nil {
		log.Error("failed to stop caddy")
	}

	// Stop all DNS-SD processes
	var wg sync.WaitGroup
	for _, dnsCmd := range dnsCommands {
		wg.Add(1)
		go func(cmd *cmd.Cmd) {
			defer wg.Done()
			err = cmd.Stop()
			if err != nil {
				log.Error("failed to stop cmd")
			}
		}(dnsCmd)
	}
	wg.Wait()
}
