package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/siyamex/XCP/internal/execx"
)

// RestoreDump runs a database dump as a temporary MariaDB user that has
// every privilege on that one database and nothing else, then drops the
// user. db has been checked by CheckMySQLName: only a-z, 0-9 and _.
func (m *MySQL) RestoreDump(ctx context.Context, run *execx.Runner, db string, dump io.Reader) error {
	c, err := m.conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	b := make([]byte, 20)
	_, _ = rand.Read(b) // never fails (crypto/rand)
	user, pass := "xcprestore"+hex.EncodeToString(b[:4]), hex.EncodeToString(b[4:])
	if _, err := c.ExecContext(ctx, fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'", user, pass)); err != nil {
		return err
	}
	defer func() { // even when the restore was canceled
		_, _ = c.ExecContext(context.WithoutCancel(ctx), fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost'", user))
	}()
	if _, err := c.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'", db, user)); err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(stripDefiners(pw, dump)) }()
	res, err := run.Run(ctx, execx.Cmd{
		Path: MariaDBClientPath, Stdin: pr, Timeout: backupMaxRuntime, MaxOutput: 64 << 10,
		Args: []string{"--protocol=SOCKET", "--socket=" + m.Socket, "--user=" + user, "--default-character-set=utf8mb4", "--max-allowed-packet=256M"},
		Env:  append(slices.Clone(execx.SafeEnv), "MYSQL_PWD="+pass),
	})
	pr.Close()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}
