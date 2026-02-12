package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/agent"
	"github.com/certkit-io/certkit-agent/config"
)

type runOptions struct {
	configPath string
	stopCh     <-chan struct{}
	runOnce    bool
	key        string
}

func runAgent(opts runOptions) {
	log.Printf("certkit-agent starting...")
	log.Printf("certkit-agent version: %s, commit: %s, date: %s", version, commit, date)
	log.Printf("certkit-agent using config: %s", opts.configPath)

	if _, err := os.Stat(opts.configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", opts.configPath)
		if err := config.CreateInitialConfig(opts.configPath, opts.key); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := config.LoadConfig(opts.configPath, Version()); err != nil {
		log.Fatal(err)
	}

	log.Printf("API Base: %s", config.CurrentConfig.ApiBase)

	if opts.runOnce {
		if agent.NeedsRegistration() {
			if config.CurrentConfig.Bootstrap == nil || strings.TrimSpace(config.CurrentConfig.Bootstrap.RegistrationKey) == "" {
				log.Fatal(fmt.Errorf("agent is not registered and no registration key is configured"))
			}

			agent.DoRegistration()
			if agent.NeedsRegistration() {
				log.Fatal(fmt.Errorf("agent registration did not complete"))
			}
		}

		agent.DoWork()
		log.Printf("certkit-agent single run complete")
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	agent.DoWork()

	for {
		select {
		case <-opts.stopCh:
			log.Printf("received stop signal, shutting down")
			return
		case <-ticker.C:
			agent.DoWork()
		}
	}
}

func runCmdLogged(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if out.Len() > 0 {
		log.Printf("Ran command: %s %s:\n%s", name, strings.Join(args, " "), strings.TrimSpace(out.String()))
	}
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}
