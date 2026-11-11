package agent

import (
	"context"
	"slices"
	"strings"
)

// Table maintenance actions.
const (
	MaintainCheck    = "check"
	MaintainRepair   = "repair"
	MaintainOptimize = "optimize"
)

// MaxMaintainTables bounds one maintenance run.
const MaxMaintainTables = 5000

// TableResult is MariaDB's verdict on one table.
type TableResult struct {
	Table string
	Type  string // status, note, warning or error: the worst reported
	Text  string
}

var maintainSQL = map[string]string{
	MaintainCheck: "CHECK TABLE ", MaintainRepair: "REPAIR TABLE ", MaintainOptimize: "OPTIMIZE TABLE ",
}

// CheckMaintainAction validates a maintenance action. The fake agent uses it too.
func CheckMaintainAction(action string) error {
	if _, ok := maintainSQL[action]; !ok {
		return invalid("action must be check, repair or optimize, not %q", action)
	}
	return nil
}

// msgRank orders MariaDB's message types from harmless to bad.
func msgRank(t string) int {
	return slices.Index([]string{"status", "info", "note", "warning", "error"}, strings.ToLower(t))
}

// verdict folds the rows MariaDB returns for one table into one result:
// the worst type, with the texts of that type.
func verdict(table string, rows [][2]string) TableResult {
	res := TableResult{Table: table, Type: "status"}
	var texts []string
	for _, r := range rows {
		t := strings.ToLower(r[0])
		switch {
		case msgRank(t) > msgRank(res.Type):
			res.Type, texts = t, []string{r[1]}
		case t == res.Type:
			texts = append(texts, r[1])
		}
	}
	res.Text = strings.Join(texts, "; ")
	if len(res.Text) > 500 {
		res.Text = strings.ToValidUTF8(res.Text[:500], "") + "..."
	}
	return res
}

// Maintain checks, repairs or optimizes every table of one of the account's
// databases, one after the other. Views are left out. Engines that cannot
// do the action say so in a note, which is not a failure.
func (m *MySQL) Maintain(ctx context.Context, username, name, action string) ([]TableResult, error) {
	if err := CheckMySQLName(username, name, MaxDatabaseName); err != nil {
		return nil, err
	}
	if err := CheckMaintainAction(action); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rows, err := c.QueryContext(ctx, `SELECT TABLE_NAME FROM information_schema.TABLES
		WHERE TABLE_SCHEMA = ? AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME LIMIT ?`, name, MaxMaintainTables+1)
	if err != nil {
		return nil, err
	}
	var tables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(tables) > MaxMaintainTables {
		return nil, invalid("database %s has more than %d tables", name, MaxMaintainTables)
	}
	out := make([]TableResult, 0, len(tables))
	for _, t := range tables {
		// Table, Op, Msg_type, Msg_text; several rows for one table.
		rs, err := c.QueryContext(ctx, maintainSQL[action]+ident(name)+"."+ident(t)) //nolint:gosec // G202: identifiers quoted by ident
		if err != nil {
			return nil, err
		}
		var msgs [][2]string
		for rs.Next() {
			var tbl, op, typ, text string
			if err := rs.Scan(&tbl, &op, &typ, &text); err != nil {
				rs.Close()
				return nil, err
			}
			msgs = append(msgs, [2]string{typ, text})
		}
		rs.Close()
		if err := rs.Err(); err != nil {
			return nil, err
		}
		out = append(out, verdict(t, msgs))
	}
	return out, nil
}
