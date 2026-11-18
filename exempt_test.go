package main

import "testing"

func TestExemptPrefix(t *testing.T) {
	pats := "chatnet/staff,chatnet/service/"
	cases := map[string]string{
		"chatnet/staff/an admin":  "chatnet/staff",
		"chatnet/service/example": "chatnet/service/",
		"Chatnet/Service/Example": "chatnet/service/",
		"chatnet/bot/crash0ver":   "",
		"CN-1234.example":         "",
		"chatnet/servicex":        "",
	}
	for host, want := range cases {
		if got := exemptPrefix(host, pats); got != want {
			t.Errorf("exemptPrefix(%q) = %q, want %q", host, got, want)
		}
	}
	if exemptPrefix("chatnet/staff/x", "") != "" {
		t.Error("empty pattern list must exempt nobody")
	}
}
