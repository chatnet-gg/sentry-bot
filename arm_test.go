package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Default state: detections fire but NOTHING is ever queued.
func TestUnarmedNeverKlines(t *testing.T) {
	b := testBot(t)
	for i := 0; i < 60; i++ {
		feed(b, fmt.Sprintf(":bot%d!~b@198.51.100.%d JOIN #chatnet", i, i))
	}
	for i := 0; i < 80; i++ {
		feed(b, ":spam!~s@203.0.113.5 PRIVMSG #chatnet :buy now")
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("unarmed channel queued %d K-lines, want 0", n)
	}
}

func TestArmExpiryAndOtherChannel(t *testing.T) {
	b := testBot(t)
	b.channels["#other"] = true
	b.klineArmed["#chatnet"] = time.Now().Add(-time.Second) // expired
	if b.klineBlocked("#chatnet", time.Now()) == "" {
		t.Fatal("expired arm must block")
	}
	arm(b, "#chatnet")
	if b.klineBlocked("#chatnet", time.Now()) != "" {
		t.Fatal("armed channel must not be blocked")
	}
	if b.klineBlocked("#other", time.Now()) == "" {
		t.Fatal("arming #chatnet must not arm #other")
	}
}

// Armed, but a probable netsplit (warm-up after a reconnect here) suspends it.
func TestArmedButWarmupBlocks(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")
	b.guard.connectedAt = time.Now() // just (re)connected
	if b.klineBlocked("#chatnet", time.Now()) == "" {
		t.Fatal("armed channel must still be blocked during the warm-up")
	}
}

// A queued K-line is dropped if the channel got disarmed meanwhile, and is
// really sent while it is still armed (so the test can fail).
func TestDisarmDropsQueuedButArmedSends(t *testing.T) {
	for _, disarm := range []bool{false, true} {
		b := testBot(t)
		var sent []string
		b.sendHook = func(s string) { sent = append(sent, s) }
		arm(b, "#chatnet")
		for i := 0; i < 40; i++ {
			feed(b, fmt.Sprintf(":bot%d!~b@198.51.100.%d JOIN #chatnet", i, i))
		}
		if len(b.klineQueue) == 0 {
			t.Fatal("armed mass-join should queue")
		}
		if disarm {
			delete(b.klineArmed, "#chatnet")
		}
		sent = nil
		b.finishPendingKline("198.51.100.1")
		got := false
		for _, s := range sent {
			if strings.HasPrefix(s, "KLINE ") {
				got = true
			}
		}
		if got == disarm {
			t.Fatalf("disarm=%v but KLINE sent=%v (%v)", disarm, got, sent)
		}
	}
}

func TestKlineCommandPermissions(t *testing.T) {
	b := testBot(t)
	b.cfg.AdminAccounts = []string{"admin"}
	b.cfg.KlineAccounts = []string{"alice", "bob"}
	for acct, want := range map[string]bool{"admin": true, "alice": true, "BOB": true, "random": false, "": false} {
		if got := b.cfg.canKline(acct); got != want {
			t.Errorf("canKline(%q)=%v want %v", acct, got, want)
		}
	}
	if b.cfg.isAdmin("alice") {
		t.Error("KLINE accounts must not become full admins")
	}
}

func TestKlineCommandFlow(t *testing.T) {
	b := testBot(t)
	b.cfg.AdminAccounts = []string{"admin"}
	b.cfg.KlineAccounts = []string{"alice"}
	var sent []string
	b.sendHook = func(s string) { sent = append(sent, s) }
	run := func(account, value string) {
		sent = nil
		b.pendingCmd = &pendingChanCmd{nick: "n", kind: "KLINE", channel: "#new", account: account, setValue: value, createdAt: time.Now()}
		b.finishPendingCmd()
	}
	run("random", "ON")
	if _, ok := b.klineArmed["#new"]; ok || !strings.Contains(strings.Join(sent, "|"), "Do I know you") {
		t.Fatalf("unauthorised account armed KLINE: %v", sent)
	}
	run("alice", "ON")
	if time.Until(b.klineArmed["#new"]) < 23*time.Hour || !b.channels["#new"] {
		t.Fatalf("ON should arm ~1 day and join: %v %v", b.klineArmed, b.channels)
	}
	run("alice", "ON 999999")
	if time.Until(b.klineArmed["#new"]) > 24*time.Hour+time.Minute {
		t.Fatal("minutes cap not enforced")
	}
	run("alice", "ON 30")
	if d := time.Until(b.klineArmed["#new"]); d > 31*time.Minute || d < 29*time.Minute {
		t.Fatalf("ON 30 gave %v", d)
	}
	run("alice", "OFF")
	if _, ok := b.klineArmed["#new"]; ok {
		t.Fatal("OFF did not disarm")
	}
}

// Unarmed detections alert the configured target and ban nobody.
func TestUnarmedAlertsTarget(t *testing.T) {
	b := testBot(t)
	b.cfg.AlertTarget = "#ops"
	var sent []string
	b.sendHook = func(s string) { sent = append(sent, s) }
	for i := 0; i < 80; i++ {
		feed(b, ":spam!~s@203.0.113.5 PRIVMSG #chatnet :buy now")
	}
	if len(b.klineQueue) != 0 || !strings.Contains(strings.Join(sent, "|"), "NOTICE #ops :[Sentry]") {
		t.Fatalf("queue=%d sent=%v", len(b.klineQueue), sent)
	}
}

// The real text of a netsplit QUIT when serverhide flatten_links is on.
func TestFlattenedNetsplitTextRecognised(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	for _, s := range b.guard.known {
		s.First -= 3600
	}
	b.klineQueue = nil
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example QUIT :*.net *.split", i, i))
	}
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("netsplit rejoin queued %d K-lines even though armed, want 0", n)
	}
}

// Whatever the QUIT text says, many members quitting at once suspends
// action; even an armed channel must not ban the people who come back.
func TestQuitBurstWithOddTextSuspendsAction(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")
	for i := 0; i < 30; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	b.klineQueue = nil
	for i := 0; i < 30; i++ { // hub reset: connection-reset style reasons
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example QUIT :Read error: Connection reset by peer", i, i))
	}
	for i := 0; i < 30; i++ {
		feed(b, fmt.Sprintf(":n%d!~n@new%d.example JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("after a quit burst %d K-lines were queued, want 0", n)
	}
}
