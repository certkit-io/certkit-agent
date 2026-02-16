//go:build windows

package main

import (
	"io"
	"log"
	"strings"
	"sync"

	"golang.org/x/sys/windows/svc/eventlog"
)

const windowsEventLogSource = "CertKit"
const windowsEventLogID uint32 = 1

var (
	windowsEventWriterOnce sync.Once
	windowsEventWriter     io.Writer
)

type windowsEventLogSink struct {
	eventLog *eventlog.Log
	mu       sync.Mutex
}

func (w *windowsEventLogSink) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	message := strings.TrimSpace(string(p))
	if message == "" {
		return len(p), nil
	}

	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		_ = w.eventLog.Info(windowsEventLogID, line)
	}

	return len(p), nil
}

func getWindowsEventWriter() io.Writer {
	windowsEventWriterOnce.Do(func() {
		el, err := eventlog.Open(windowsEventLogSource)
		if err != nil {
			return
		}
		windowsEventWriter = &windowsEventLogSink{eventLog: el}
	})

	return windowsEventWriter
}

func setLogOutputWithEventLog(base io.Writer) {
	eventWriter := getWindowsEventWriter()
	if eventWriter == nil {
		log.SetOutput(base)
		return
	}

	log.SetOutput(io.MultiWriter(base, eventWriter))
}
