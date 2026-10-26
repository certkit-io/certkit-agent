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
	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/selfupdate"
)

type runOptions struct {
	configPath  string
	stopCh      <-chan struct{}
	runOnce     bool
	key         string
	serviceName string
}

func runAgent(opts runOptions) {
	log.Printf("certkit-agent starting...")
	log.Printf("certkit-agent version: %s, commit: %s, date: %s", version, commit, date)
	log.Printf("certkit-agent using config: %s", opts.configPath)

	if _, err := os.Stat(opts.configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", opts.configPath)
		if err := config.CreateInitialConfig(opts.configPath, opts.key, opts.serviceName); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := config.LoadConfig(opts.configPath, Version()); err != nil {
		log.Fatal(err)
	}

	log.Printf("API Base: %s", config.CurrentConfig.ApiBase)

	api.SetStopChannel(opts.stopCh)
	agent.InitKeystoreFromConfig()

	registeredOnStartup := false
	if agent.NeedsRegistration() {
		if config.CurrentConfig.Bootstrap == nil || strings.TrimSpace(config.CurrentConfig.Bootstrap.RegistrationKey) == "" {
			log.Fatal(fmt.Errorf("agent is not registered and no registration key is configured"))
		}

		agent.DoRegistration()
		if agent.NeedsRegistration() {
			log.Fatal(fmt.Errorf("agent registration did not complete"))
		}
		registeredOnStartup = true
	}

	if opts.runOnce {
		agent.PollAndSync(true)
		log.Printf("certkit-agent single run complete")
		return
	}

	if !opts.runOnce && !registeredOnStartup {
		agent.SendInventory()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	agent.PollAndSync(true)

	for {
		select {
		case <-opts.stopCh:
			log.Printf("received stop signal, shutting down")
			return
		case <-ticker.C:
			// A sync that runs past 30 seconds leaves a tick waiting alongside
			// any stop request that came in meanwhile, and select picks between
			// ready cases at random, so check for a stop before syncing again.
			if stopRequested(opts.stopCh) {
				log.Printf("received stop signal, shutting down")
				return
			}
			agent.PollAndSync(false)
			if selfupdate.HandleUpdateIfNeeded(opts.configPath) {
				selfupdate.TriggerRestart()
			}
		}
	}
}

// stopRequested reports whether stopCh has been closed, without waiting.
func stopRequested(stopCh <-chan struct{}) bool {
	select {
	case <-stopCh:
		return true
	default:
		return false
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
