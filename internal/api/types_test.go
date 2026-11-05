package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsDangerousInput(t *testing.T) {
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	tooLong := time.Now().Add(48 * time.Hour).Format(time.RFC3339)
	cases := []struct {
		name, taskType, payload string
	}{
		{"option injection", TaskPkgInstall, `{"packages":["--installroot=/tmp"]}`},
		{"package url", TaskPkgInstall, `{"packages":["https://evil.example/x.rpm"]}`},
		{"package path", TaskPkgInstall, `{"packages":["/tmp/x.rpm"]}`},
		{"shell metachar", TaskPkgInstall, `{"packages":["vim;id"]}`},
		{"no packages", TaskPkgInstall, `{"packages":[]}`},
		{"unknown field", TaskPkgInstall, `{"packages":["vim"],"extra":1}`},
		{"unknown type", "shell.exec", `{}`},
		{"relative path", TaskFilePut, `{"path":"etc/x","content":""}`},
		{"path traversal", TaskFilePut, `{"path":"/etc/hauswart.d/../shadow","content":""}`},
		{"bad mode", TaskFilePut, `{"path":"/etc/hauswart.d/x","content":"","mode":"4755x"}`},
		{"setuid mode", TaskFilePut, `{"path":"/etc/hauswart.d/x","content":"","mode":"4755"}`},
		{"sudo for root", TaskSudoGrant, `{"user":"root","expires_at":"` + soon + `"}`},
		{"sudoers injection", TaskSudoGrant, `{"user":"a ALL=(ALL) ALL\nb","expires_at":"` + soon + `"}`},
		{"sudo without expiry", TaskSudoGrant, `{"user":"anna"}`},
		{"sudo too long", TaskSudoGrant, `{"user":"anna","expires_at":"` + tooLong + `"}`},
		{"sudo command injection", TaskSudoGrant, `{"user":"anna","expires_at":"` + soon + `","commands":["/bin/ls, ALL"]}`},
		{"sudo relative command", TaskSudoGrant, `{"user":"anna","expires_at":"` + soon + `","commands":["ls"]}`},
		{"wheel membership", TaskUserCreate, `{"user":"anna","groups":["wheel"]}`},
		{"docker membership", TaskUserCreate, `{"user":"anna","groups":["docker"]}`},
		{"passwd injection", TaskUserCreate, `{"user":"anna","full_name":"a:b"}`},
		{"lock root", TaskUserLock, `{"user":"root"}`},
		{"empty limit", TaskLimitSet, `{"user":"anna"}`},
		{"negative limit", TaskLimitSet, `{"user":"anna","memory_mb":-1}`},
		{"clear text password", TaskUserPassword, `{"user":"anna","hash":"secret"}`},
		{"weak hash", TaskUserPassword, `{"user":"anna","hash":"$1$abc$def"}`},
		{"chpasswd line injection", TaskUserPassword, `{"user":"anna","hash":"$6$a$` + strings.Repeat("a", 86) + `\nroot:x"}`},
		{"password for root", TaskUserPassword, `{"user":"root","hash":"$6$a$` + strings.Repeat("a", 86) + `"}`},
		{"ca name traversal", TaskCAInstall, `{"name":"../x","pem":"-----BEGIN CERTIFICATE-----"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Validate(c.taskType, json.RawMessage(c.payload)); err == nil {
				t.Fatalf("accepted %s", c.payload)
			}
		})
	}
}

func TestValidateAcceptsNormalInput(t *testing.T) {
	soon := time.Now().Add(time.Hour).Format(time.RFC3339)
	cases := []struct{ taskType, payload string }{
		{TaskPkgInstall, `{"packages":["vim-enhanced","gcc-c++","libfoo1:amd64"]}`},
		{TaskFlatpakInstall, `{"packages":["org.mozilla.firefox"]}`},
		{TaskPkgUpgrade, `{}`},
		{TaskFilePut, `{"path":"/etc/hauswart.d/a.conf","content":"x","mode":"0644"}`},
		{TaskSudoGrant, `{"user":"anna","expires_at":"` + soon + `"}`},
		{TaskSudoGrant, `{"user":"anna","expires_at":"` + soon + `","commands":["/usr/bin/dnf"]}`},
		{TaskUserCreate, `{"user":"anna","full_name":"Anna B","groups":["video"]}`},
		{TaskLimitSet, `{"user":"anna","cpu_percent":200,"memory_mb":4096}`},
		{TaskUserPassword, `{"user":"anna","hash":"$6$salt$` + strings.Repeat("a", 86) + `"}`},
		{TaskUserPassword, `{"user":"anna","hash":"$6$rounds=5000$salt$` + strings.Repeat("a", 86) + `"}`},
	}
	for _, c := range cases {
		if err := Validate(c.taskType, json.RawMessage(c.payload)); err != nil {
			t.Errorf("%s %s: %v", c.taskType, c.payload, err)
		}
	}
}
