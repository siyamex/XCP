//go:build !unix

package execx

import "os/exec"

func setProcAttrs(*exec.Cmd) {}
