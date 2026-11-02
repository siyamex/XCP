package install

import (
	"context"
	"os"
	"path"

	"github.com/siyamex/XCP/internal/agent"
)

// FTP units (ADR-0010). XCP's own pure-ftpd.service overrides the one
// systemd generates from Ubuntu's SysV script.
const (
	FTPUnit     = "pure-ftpd.service"
	FTPAuthUnit = "xcp-ftpauth.service"
)

const ftpUnit = `# Managed by XCP (xcp-install; ADR-0010). Changes are overwritten.
[Unit]
Description=Pure-FTPd FTP server (logins checked by xcp-ftpauth)
After=network.target ` + FTPAuthUnit + `
Wants=` + FTPAuthUnit + `

[Service]
ExecStart=/usr/sbin/pure-ftpd ` + agent.FTPConfFile + `
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`

// ftpAuthUnit runs xcp-ftpauth as root without capabilities, except
// reading folders it does not own (a login's folder may be inside
// public_html, which only the user and the web server may enter).
const ftpAuthUnit = `# Managed by XCP (xcp-install; ADR-0010). Changes are overwritten.
[Unit]
Description=XCP FTP login checks for Pure-FTPd
Before=` + FTPUnit + `

[Service]
ExecStart=/usr/sbin/xcp-ftpauth
RuntimeDirectory=xcp-ftpauth
RuntimeDirectoryMode=0700
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
MemoryMax=512M
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
`

func (in *installer) ftp(ctx context.Context) error {
	if in.o.NoFTP {
		in.logf("    skipped (--no-ftp)")
		return nil
	}
	if in.o.DryRun {
		in.logf("    would install pure-ftpd, write its configuration and start xcp-ftpauth")
		return nil
	}
	installed, err := in.o.Sys.InstallFTPServer(ctx)
	if err != nil {
		return err
	}
	if installed {
		in.changed("installed pure-ftpd")
	}
	if err := in.makeDirs([]dirSpec{
		{path.Dir(agent.FTPFragmentDir), 0o700, rootRoot},
		{agent.FTPFragmentDir, 0o700, rootRoot},
		{path.Dir(agent.FTPConfFile), 0o755, rootRoot},
		{path.Dir(agent.FTPXferLog), 0o755, rootRoot},
	}); err != nil {
		return err
	}
	cert, key := CertFile, KeyFile
	if _, err := os.Stat(in.path(HostCertFile)); err == nil {
		cert, key = HostCertFile, HostKeyFile
	}
	conf, err := in.writeFile(agent.FTPConfFile, []byte(agent.FTPConfig(cert, key)), 0o644, rootRoot, false)
	if err != nil {
		return err
	}
	units := false
	for _, u := range []struct{ name, content string }{{FTPUnit, ftpUnit}, {FTPAuthUnit, ftpAuthUnit}} {
		wrote, err := in.writeFile(UnitDir+"/"+u.name, []byte(u.content), 0o644, rootRoot, false)
		if err != nil {
			return err
		}
		units = units || wrote
	}
	if units {
		if err := in.o.Sys.Systemctl(ctx, "daemon-reload"); err != nil {
			return err
		}
	}
	if err := in.o.Sys.Systemctl(ctx, "enable", "--now", FTPAuthUnit, FTPUnit); err != nil {
		return err
	}
	// in.restart: the binaries changed, xcp-ftpauth among them.
	if units || in.restart {
		if err := in.o.Sys.Systemctl(ctx, "restart", FTPAuthUnit); err != nil {
			return err
		}
	}
	if units || conf || installed {
		return in.o.Sys.Systemctl(ctx, "restart", FTPUnit)
	}
	return nil
}
