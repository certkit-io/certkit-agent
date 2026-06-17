package inventory

import (
	"encoding/xml"
	"errors"
	"log"
	"runtime"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

// Minimal structure that gets the data we need from settings.xml
type FileZillaSettingsXml struct {
	FtpServer struct {
		Session struct {
			Pasv struct {
				HostOverride string `xml:"host_override"`
			} `xml:"pasv"`
			Tls struct {
				Key struct {
					Text string `xml:",chardata"`
					Type string `xml:"type,attr"`
				} `xml:"key"`
				Certs struct {
					Text string `xml:",chardata"`
					Type string `xml:"type,attr"`
				} `xml:"certs"`
			} `xml:"tls"`
		} `xml:"session"`
	} `xml:"ftp_server"`
} 

type FileZillaProvider struct{}

func (FileZillaProvider) Name() string {
	return "filezilla"
}

func (FileZillaProvider) Collect() ([]api.InventoryItem, error) {
	configFiles, err := expandConfigGlobs(fileZillaConfigGlobs())
	if err != nil {
		return nil, err
	}

	items := make([]api.InventoryItem, 0)
	for _, path := range configFiles {
		certs, keys, domains, err := parseFileZillaConfig(path)
		if err != nil {
			log.Printf("Inventory parse error for %s: %v", path, err)
			continue
		}

		pairs := len(certs)
		if len(keys) < pairs {
			pairs = len(keys)
		}
		for i := 0; i < pairs; i++ {
			items = append(items, api.InventoryItem{
				Server:          "filezilla",
				ConfigPath:      path,
				CertificatePath: certs[i],
				KeyPath:         keys[i],
				Domains:         joinDomains(domains),
			})
		}
	}

	return items, nil
}

func fileZillaConfigGlobs() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\ProgramData\filezilla-server\settings.xml`,
		}
	}

	return []string{
		"/opt/filezilla-server/etc/settings.xml",
	}
}

func parseFileZillaConfig(path string) ([]string, []string, []string, error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return nil, nil, nil, err
	}

	var settings FileZillaSettingsXml
	err = xml.Unmarshal(data, &settings)
	if err != nil {
		return nil, nil, nil, err
	}

	if settings.FtpServer.Session.Tls.Certs.Type != "filepath" {
		return nil, nil, nil, errors.New("TLS certificate must be set to 'Path to file'")
	}
	if settings.FtpServer.Session.Tls.Key.Type != "filepath" {
		return nil, nil, nil, errors.New("TLS private key must be set to 'Path to file'")
	}

	var certs []string
	var keys []string
	var domains []string

	certs = append(certs, strings.TrimSpace(settings.FtpServer.Session.Tls.Certs.Text))
	keys = append(keys, strings.TrimSpace(settings.FtpServer.Session.Tls.Key.Text))
	domains = append(domains, strings.TrimSpace(settings.FtpServer.Session.Pasv.HostOverride))

	return certs, keys, domains, nil
}
