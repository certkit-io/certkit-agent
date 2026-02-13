package utils

import (
	"log"
	"sync"
)

var authStateMu sync.Mutex
var wasUnauthorized bool

func MarkAgentUnauthorized() {
	authStateMu.Lock()
	defer authStateMu.Unlock()
	wasUnauthorized = true
	log.Printf("Agent is not currently authorized. Waiting for authorization from the CertKit server.")
}

func MarkAgentAuthorized() {
	authStateMu.Lock()
	defer authStateMu.Unlock()
	if !wasUnauthorized {
		return
	}
	wasUnauthorized = false
	log.Printf("Agent is now authorized; beginning to poll for configuration changes.")
}

func IsAgentUnauthorized() bool {
	authStateMu.Lock()
	defer authStateMu.Unlock()
	return wasUnauthorized
}
