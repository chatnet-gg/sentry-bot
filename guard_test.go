package main

import (
	"fmt"
	"testing"
	"time"
)

func testBot(t *testing.T) *Bot {
	t.Setenv("SENTRY_NICKSERV_PASSWORD", "x")
	t.Setenv("SENTRY_OPER_PASSWORD", "x")
	t.Setenv("SENTRY_STATE_FILE", t.TempDir()+"/settings.json")
	cfg := loadConfig()
	b := &Bot{
		cfg:              cfg,
		nicks:            make(map[string]*nickState),
		joins:            make(map[string][]joinEvent),
		channels:         map[string]bool{"#chatnet": true},
		channelOverrides: map[string]map[string]string{},
		guard:            newGuard(t.TempDir() + "/known.json"),
		klineArmed:       map[string]time.Time{},
		lastAlert:        map[string]time.Time{},
		notifySent:       map[string]time.Time{},
		notifyDone:       map[string]bool{},
	}
	// past the warm-up, as in a bot that has been up for a while
	b.guard.connectedAt = time.Now().Add(-time.Hour)
	return b
}

// arm simulates a staff member having run KLINE <ch> ON.
func arm(b *Bot, ch string) { b.klineArmed[ch] = time.Now().Add(time.Hour) }

func feed(b *Bot, raw string) { b.dispatch(parseLine(raw)) }

// 200 users are in the channel (Sentry has seen their NAMES), a netsplit
// QUITs them all, the link comes back and they all JOIN within seconds.
func TestNetsplitRejoinIsNotAnAttack(t *testing.T) {
	b := testBot(t)
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	// they were genuinely here a while: make those hosts established
	for _, s := range b.guard.known {
		s.First -= 3600
	}
	b.klineQueue = nil
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example QUIT :hub.chatnet.gg London.UK.EU.ChatNet.Gg", i, i))
	}
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("netsplit rejoin queued %d K-lines, want 0", n)
	}
}

// Users who were only on the far side of the split (never seen by us)
// arrive in the same netjoin burst.
func TestUnknownUsersInsideNetjoinBurstAreTolerated(t *testing.T) {
	b := testBot(t)
	feed(b, ":a!~a@h1.example JOIN #chatnet")
	feed(b, ":a!~a@h1.example QUIT :hub.chatnet.gg London.UK.EU.ChatNet.Gg")
	feed(b, ":a!~a@h1.example JOIN #chatnet") // opens the netjoin window
	for i := 0; i < 100; i++ {
		feed(b, fmt.Sprintf(":far%d!~f@far%d.example JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("netjoin burst queued %d K-lines, want 0", n)
	}
}

// A real clone army: many brand new hosts, no split, no netjoin.
func TestRealMassJoinStillCaught(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")
	for i := 0; i < 40; i++ {
		feed(b, fmt.Sprintf(":bot%d!~b@198.51.100.%d JOIN #chatnet", i, i))
	}
	if len(b.klineQueue) == 0 {
		t.Fatal("40 brand-new hosts joining at once were not actioned")
	}
}

// Same host 200 times is still a clone army (must not look "known" after
// the first one).
func TestClonesFromOneHostStillCaught(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")
	for i := 0; i < 40; i++ {
		feed(b, fmt.Sprintf(":c%d!~c@203.0.113.9 JOIN #chatnet", i))
	}
	if len(b.klineQueue) == 0 {
		t.Fatal("40 clones from one host were not actioned")
	}
}

// Hub reboot / Sentry restart: it forgets everyone, the channel refills.
// Hosts persisted from earlier runs are known, and NAMES with
// userhost-in-names bootstraps the rest.
func TestRestartWithKnownHostsAndWarmup(t *testing.T) {
	b := testBot(t)
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 200; i++ {
		b.guard.known[fmt.Sprintf("host%d.example", i)] = &hostSeen{First: old.Unix(), Last: old.Unix()}
	}
	b.guard.reset(time.Now()) // fresh connect
	for i := 0; i < 200; i++ {
		feed(b, fmt.Sprintf(":u%d!~u@host%d.example JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("known hosts rejoining after a restart queued %d K-lines", n)
	}
	// and even completely unknown hosts are not actioned during warm-up
	for i := 0; i < 40; i++ {
		feed(b, fmt.Sprintf(":n%d!~n@198.51.100.%d JOIN #chatnet", i, i))
	}
	if n := len(b.klineQueue); n != 0 {
		t.Fatalf("warm-up still actioned %d joins", n)
	}
}

func TestNamesBootstrapsKnownHosts(t *testing.T) {
	b := testBot(t)
	b.guard.reset(time.Now())
	feed(b, ":hub.chatnet.gg 353 Sentry = #chatnet :@op!~o@opcloak.example +v!~v@v.example plain!~p@p.example")
	if !b.guard.isMember("#chatnet", "op") || !b.guard.isMember("#chatnet", "plain") {
		t.Fatal("NAMES did not populate membership")
	}
	if !b.guard.isKnown("p.example", time.Now()) {
		t.Fatal("host from NAMES (userhost-in-names) should be established/known")
	}
}

func TestAlreadyInChannelIgnored(t *testing.T) {
	b := testBot(t)
	b.guard.addMember("#chatnet", "alice", "a.example")
	if why := b.guard.classifyJoin("#chatnet", "Alice", "a.example", time.Now()); why != "already in channel" {
		t.Fatalf("got %q", why)
	}
}

func TestInfrastructureNeverActioned(t *testing.T) {
	b := testBot(t)
	arm(b, "#chatnet")                           // even when armed, infrastructure is never actioned
	b.guard.infraIPs = "192.0.2.10,2001:db8::10" // documentation addresses, standing in for the operator's own servers
	for _, h := range []string{"services.chatnet.gg", "bouncer.chatnet.gg", "172.16.5.9", "172.20.0.2", "10.1.2.3", "127.0.0.1", "chatnet/bot/example", "chatnet/service/example", "192.0.2.10", "2001:db8::10"} {
		if !isInfraHost(h, b.guard.infraSufx, b.guard.infraIPs) {
			t.Errorf("%q should count as infrastructure", h)
		}
		b.action("x", h, "test", "#chatnet")
	}
	if len(b.klineQueue) != 0 {
		t.Fatalf("infrastructure got queued: %d", len(b.klineQueue))
	}
	for _, h := range []string{"CN-ec-63606.ilkley.irccloud.com", "86-87-194-18.fixed.kpn.net", "198.51.100.7", "chatnet.gg.evil.example"} {
		if isInfraHost(h, b.guard.infraSufx, b.guard.infraIPs) {
			t.Errorf("%q must NOT count as infrastructure", h)
		}
	}
}

func TestSplitReason(t *testing.T) {
	yes := []string{"hub.chatnet.gg London.UK.EU.ChatNet.Gg", "a.b c.d", "*.net *.split"}
	no := []string{"Quit: *.net *.split", "*.net *.join", "*.net", "Quit: hub.chatnet.gg London.UK.EU.ChatNet.Gg", "Ping timeout: 240 seconds", "Read error: Connection reset by peer", "bye", "hello world", ""}
	for _, r := range yes {
		if !isSplitReason(r) {
			t.Errorf("%q should be a split reason", r)
		}
	}
	for _, r := range no {
		if isSplitReason(r) {
			t.Errorf("%q must not be a split reason", r)
		}
	}
}

func TestCircuitBreaker(t *testing.T) {
	g := newGuard("")
	now := time.Now()
	for i := 0; i < g.maxKlines; i++ {
		if !g.allowKline(now) {
			t.Fatalf("K-line %d refused too early", i)
		}
	}
	if g.allowKline(now) {
		t.Fatal("breaker did not trip")
	}
	if g.allowKline(now.Add(5 * time.Minute)) {
		t.Fatal("breaker must stay open during the pause")
	}
	if !g.allowKline(now.Add(g.breakerFor + time.Minute)) {
		t.Fatal("breaker must close after the pause")
	}
}

func TestOffByDefault(t *testing.T) {
	b := testBot(t)
	if b.cfg.AutoJoin {
		t.Fatal("AutoJoin must default to false")
	}
}
