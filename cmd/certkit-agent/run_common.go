package main

import (
	"log"
	"os"
	"time"

	"github.com/certkit-io/certkit-agent/agent"
	"github.com/certkit-io/certkit-agent/config"
)

func runAgent(configPath string, stopCh <-chan struct{}) {
	log.Printf("certkit-agent run starting (config=%s)", configPath)
	log.Printf("certkit-agent version: %s, commit: %s, date: %s", version, commit, date)

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
