package main

import (
	"strings"
	"testing"
)

func TestAutoJoinChannels(t *testing.T) {
	t.Setenv("SENTRY_AUTOJOIN_CHANNELS", "#ops,#main,bad name")
	b := testBot(t)
	if len(b.cfg.AutoJoinChannels) != 3 {
		t.Fatalf("config: %v", b.cfg.AutoJoinChannels)
	}
	var sent []string
	b.sendHook = func(s string) { sent = append(sent, s) }
	feed(b, ":srv 001 Sentry :Welcome")
	joined := strings.Join(sent, "|")
	if !strings.Contains(joined, "JOIN #ops") || !strings.Contains(joined, "JOIN #main") || strings.Contains(joined, "bad name") {
		t.Fatalf("joins: %v", sent)
	}
}

// Being in the channel is harmless: nothing gets banned until a person arms it.
func TestAutoJoinedChannelIsNotArmed(t *testing.T) {
	t.Setenv("SENTRY_AUTOJOIN_CHANNELS", "#chatnet")
	b := testBot(t)
	for i := 0; i < 60; i++ {
		feed(b, ":spam!~s@203.0.113.5 PRIVMSG #chatnet :buy now")
	}
	if len(b.klineQueue) != 0 {
		t.Fatalf("auto-joined but unarmed channel queued %d K-lines", len(b.klineQueue))
	}
}
