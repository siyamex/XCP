package agent

import (
	"strings"
	"testing"
)

func TestWebOptionsClean(t *testing.T) {
	good := WebOptions{
		ErrorPages: map[string]string{"404": "/errors/404.html", "500": ""},
		Hotlink:    Hotlink{Enabled: true, Hosts: []string{"Partner.example", "partner.example"}, Extensions: []string{".JPG", "png", "jpg"}},
		Blocked:    []string{"203.0.113.9", "198.51.100.0/24", "203.0.113.9/32", "2001:db8::/32"},
		Compress:   true,
		CacheRules: []CacheRule{{Extensions: []string{"css", "js"}, Days: 30}},
	}
	c, err := good.Clean()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ErrorPages) != 1 || len(c.Blocked) != 3 || len(c.Hotlink.Hosts) != 1 || len(c.Hotlink.Extensions) != 2 {
		t.Errorf("not normalised: %+v", c)
	}
	for name, o := range map[string]WebOptions{
		"code":        {ErrorPages: map[string]string{"418": "/x.html"}},
		"path":        {ErrorPages: map[string]string{"404": "/../etc/passwd"}},
		"quote":       {ErrorPages: map[string]string{"404": "/a\"b"}},
		"relative":    {ErrorPages: map[string]string{"404": "errors/404.html"}},
		"ip":          {Blocked: []string{"not-an-ip"}},
		"everyone":    {Blocked: []string{"0.0.0.0/0"}},
		"injection":   {Blocked: []string{"1.2.3.4\nRequire all granted"}},
		"host":        {Hotlink: Hotlink{Enabled: true, Hosts: []string{"a b"}, Extensions: []string{"jpg"}}},
		"no types":    {Hotlink: Hotlink{Enabled: true}},
		"bad type":    {Hotlink: Hotlink{Enabled: true, Extensions: []string{"jp|g"}}},
		"days":        {CacheRules: []CacheRule{{Extensions: []string{"css"}, Days: 0}}},
		"dup caching": {CacheRules: []CacheRule{{Extensions: []string{"css"}, Days: 1}, {Extensions: []string{"css"}, Days: 2}}},
	} {
		if _, err := o.Clean(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWebOptionsRender(t *testing.T) {
	o, err := WebOptions{
		ErrorPages: map[string]string{"404": "/errors/404.html"},
		Hotlink:    Hotlink{Enabled: true, Hosts: []string{"partner.example"}, Extensions: []string{"jpg", "png"}, AllowEmpty: true},
		Compress:   true,
		CacheRules: []CacheRule{{Extensions: []string{"css"}, Days: 7}},
	}.Clean()
	if err != nil {
		t.Fatal(err)
	}
	got := o.directives("shop.example")
	for _, want := range []string{
		`ErrorDocument 404 "/errors/404.html"`,
		`RewriteCond %{HTTP_REFERER} !^$`,
		`(shop\.example|partner\.example)`,
		`RewriteRule "\.(jpg|png)$" - [F,NC]`,
		`DEFLATE`,
		`ExpiresDefault "access plus 7 days"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if (WebOptions{}).directives("x.example") != "" {
		t.Error("empty options render something")
	}
}

const testHash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"

func TestProtectedDirsClean(t *testing.T) {
	good := WebOptions{ProtectedDirs: []ProtectedDir{
		{Path: "/private/", Users: []HtUser{{Name: "zed", Hash: testHash}, {Name: "amy@example.test", Hash: testHash}}},
		{Path: "/admin", Realm: "Staff only"},
	}}
	c, err := good.Clean()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.ProtectedDirs) != 2 || c.ProtectedDirs[0].Path != "/admin" || c.ProtectedDirs[1].Path != "/private" || c.ProtectedDirs[1].Realm != "Restricted area" ||
		c.ProtectedDirs[1].Users[0].Name != "amy@example.test" {
		t.Errorf("%+v", c.ProtectedDirs)
	}
	for name, d := range map[string]ProtectedDir{
		"root":     {Path: "/"},
		"dots":     {Path: "/a/../b"},
		"relative": {Path: "private"},
		"quote":    {Path: "/a\"b"},
		"realm":    {Path: "/a", Realm: "bad\"realm"},
		"user":     {Path: "/a", Users: []HtUser{{Name: "a b", Hash: testHash}}},
		"colon":    {Path: "/a", Users: []HtUser{{Name: "a:b", Hash: testHash}}},
		"no hash":  {Path: "/a", Users: []HtUser{{Name: "amy"}}},
		"plain":    {Path: "/a", Users: []HtUser{{Name: "amy", Hash: "secret"}}},
		"newline":  {Path: "/a", Users: []HtUser{{Name: "amy", Hash: testHash + "\nroot:x"}}},
		"dup user": {Path: "/a", Users: []HtUser{{Name: "amy", Hash: testHash}, {Name: "amy", Hash: testHash}}},
	} {
		if _, err := (WebOptions{ProtectedDirs: []ProtectedDir{d}}).Clean(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (WebOptions{ProtectedDirs: []ProtectedDir{{Path: "/a"}, {Path: "/a/"}}}).Clean(); err == nil {
		t.Error("a folder listed twice")
	}
}
