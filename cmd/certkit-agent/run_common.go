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

func runAgent(configPath string, stopCh <-chan struct{}) {
	log.Printf("certkit-agent run starting...")
	log.Printf("certkit-agent version: %s, commit: %s, date: %s", version, commit, date)
	log.Printf("certkit-agent using config: %s", configPath)

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Config not found, creating %s", configPath)
		if err := config.CreateInitialConfig(configPath); err != nil {
			log.Fatal(err)
		}
	}

	if _, err := config.LoadConfig(configPath, Version()); err != nil {
		log.Fatal(err)
	}

	log.Printf("API Base: %s", config.CurrentConfig.ApiBase)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	agent.DoWork()

	for {
		select {
		case <-stopCh:
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
