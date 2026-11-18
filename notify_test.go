package main

import (
	"strings"
	"testing"
	"time"
)

func TestKlineAccessNoticeOnceAndRetry(t *testing.T) {
	b := testBot(t)
	b.cfg.KlineAccounts = []string{"alice", "bob"}
	var sent []string
	b.sendHook = func(s string) { sent = append(sent, s) }
	now := time.Now()

	b.tickNotify(now) // not ready yet (before registration plus the delay)
	if len(sent) != 0 {
		t.Fatalf("sent before ready: %v", sent)
	}
	b.notifyReady = now.Add(-time.Second)
	b.tickNotify(now)
	if len(sent) != 2 || !strings.HasPrefix(sent[0], "PRIVMSG alice :") {
		t.Fatalf("want 2 PRIVMSGs, got %v", sent)
	}
	// alice is offline: 401 -> must be retried; bob got it.
	feed(b, ":srv 401 Sentry alice :No such nick/channel")
	sent = nil
	b.tickNotify(now.Add(20 * time.Second))
	if !b.notifyDone["bob"] || b.notifyDone["alice"] {
		t.Fatalf("done=%v", b.notifyDone)
	}
	b.tickNotify(now.Add(11 * time.Minute))
	if len(sent) != 1 || !strings.HasPrefix(sent[0], "PRIVMSG alice :") {
		t.Fatalf("retry should target only alice: %v", sent)
	}
	// remembered across restarts
	b2 := testBot(t)
	b2.cfg = b.cfg
	b2.loadNotified()
	if !b2.notifyDone["bob"] {
		t.Fatal("notified state not persisted")
	}
}
