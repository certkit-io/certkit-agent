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
	path, found := firstFileZillaConfigPath()
	if !found {
		return nil, nil
	}

	cert, key, domains, err := parseFileZillaConfig(path)
	if err != nil {
		log.Printf("Inventory parse error for %s: %v", path, err)
		return nil, nil
	}
	if cert == "" || key == "" {
		return nil, nil
	}

	return []api.InventoryItem{
		{
			Server:          "filezilla",
			ConfigPath:      path,
			CertificatePath: cert,
			KeyPath:         key,
			Domains:         joinDomains(domains),
		},
	}, nil
}

func firstFileZillaConfigPath() (string, bool) {
	paths := []string{
		"/opt/filezilla-server/etc/settings.xml",
		"/etc/filezilla-server/settings.xml",
		"/usr/local/etc/filezilla-server/settings.xml",
		"/var/lib/filezilla-server/settings.xml",
		"/root/.config/filezilla-server/settings.xml",
	}
	if runtime.GOOS == "windows" {
		paths = []string{
			`C:\ProgramData\filezilla-server\settings.xml`,
			`C:\Windows\System32\config\systemprofile\AppData\Local\filezilla-server\settings.xml`,
			`C:\Windows\SysWOW64\config\systemprofile\AppData\Local\filezilla-server\settings.xml`,
			`C:\Program Files\FileZilla Server\settings.xml`,
			`C:\Program Files (x86)\FileZilla Server\settings.xml`,
		}
	}

	for _, path := range paths {
		exists, err := utils.FileExists(path)
		if err != nil {
			log.Printf("Inventory FileZilla path check error for %s: %v", path, err)
			return "", false
		}
		if exists {
			return path, true
		}
	}
	return "", false
}

func parseFileZillaConfig(path string) (cert string, key string, domains []string, err error) {
	data, err := utils.ReadFileBytes(path)
	if err != nil {
		return "", "", nil, err
	}

	var settings FileZillaSettingsXml
	err = xml.Unmarshal(data, &settings)
	if err != nil {
		return "", "", nil, err
	}

	if settings.FtpServer.Session.Tls.Certs.Text != "" || settings.FtpServer.Session.Tls.Key.Text != "" {
		if !fileZillaPathSettingIsFile(settings.FtpServer.Session.Tls.Certs.Type) {
			return "", "", nil, errors.New("TLS certificate is not a file path")
		}
		if !fileZillaPathSettingIsFile(settings.FtpServer.Session.Tls.Key.Type) {
			return "", "", nil, errors.New("TLS private key is not a file path")
		}
		cert = cleanConfigValue(settings.FtpServer.Session.Tls.Certs.Text)
		key = cleanConfigValue(settings.FtpServer.Session.Tls.Key.Text)
	}
	appendFileZillaDomains(&domains, settings.FtpServer.Session.Pasv.HostOverride)

	return cert, key, domains, nil
}

func fileZillaPathSettingIsFile(settingType string) bool {
	settingType = strings.TrimSpace(settingType)
	return settingType == "" || strings.EqualFold(settingType, "filepath")
}

func appendFileZillaDomains(domains *[]string, value string) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})
	for _, field := range fields {
		if domain, ok := normalizeDomain(field); ok {
			*domains = append(*domains, domain)
		}
	}
}
