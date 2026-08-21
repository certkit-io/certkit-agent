// Legacy module file for the Windows Server 2008 R2 / 2012 R2 build.
//
// Used ONLY via `go1.20.14 build -modfile=legacy/go.legacy.mod ...` (see legacy/build.ps1).
// The normal Go 1.24 toolchain never reads this file. It is intentionally NOT named
// go.mod so it does not create a nested module boundary in the main tree.
//
// Go 1.20 is the last release that runs on Windows 7 / 8 / Server 2008 R2 / 2012 R2.
// x/sys and x/crypto are pinned to the last versions whose go directive is <= 1.20.
module github.com/certkit-io/certkit-agent

go 1.20

require (
	golang.org/x/crypto v0.17.0
	golang.org/x/sys v0.15.0
)

require github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
