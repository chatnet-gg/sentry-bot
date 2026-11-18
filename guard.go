package main

// guard.go -- keeps the mass-join check from K-lining people who are only
// coming back (2026-10-19, after the 2026-10-18 incident: a hub reset made
// everybody rejoin at once, the 15-joins-in-15s rule read it as a clone
// army and K-lined ~20 hosts, services and the bots included).
//
// What a rejoin looks like from a client's seat, and what this file does
// about each case:
//   - netsplit: the ircd sends a QUIT for everyone on the far side with the
//     reason "<server> <server>"; when the link comes back they JOIN again.
//     We remember those nicks, and a JOIN from one of them is a netjoin,
//     not a new arrival. Users who were only on the far side and never in
//     our channel ride along in the same burst, so a netjoin also opens a
//     short window in which unknown hosts are not counted either.
//   - already in the channel: JOINs for a nick we already see in the
//     channel are ignored (membership is tracked from NAMES/JOIN/PART/
//     QUIT/KICK/NICK).
//   - hosts we have seen before: a host that has been in a monitored
//     channel for a while is "known" (persisted to disk, so it also covers
//     a hub reboot/Sentry restart). A clone army is made of NEW hosts.
//   - services, bots, staff and our own boxes: never counted, never K-lined
//     (checked again on the real host right before the KLINE).
//   - just after Sentry (re)connects it knows nobody yet: warm-up period.
//   - last resort: a circuit breaker caps the number of K-lines per
//     10 minutes, whatever the detectors say.

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

// solanum/cnircd netsplit QUIT reason: two server names, nothing else.
// A user's own quit text is always prefixed "Quit: " by the ircd, so it
// can't be forged into this shape.
var splitReasonRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9.-]+ [A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z0-9.-]+$`)

func isSplitReason(reason string) bool {
	return splitReasonRe.MatchString(strings.TrimSpace(reason))
}

// isInfraHost reports whether host belongs to the network itself: any
// chatnet/ cloak (staff, services, bots), the configured domain suffixes
// (services and bouncers use <name>.chatnet.gg), private/loopback
// addresses (container bridge IPs) and the configured server IPs.
func isInfraHost(host, suffixes, ips string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return false
	}
	if strings.HasPrefix(h, "chatnet/") {
		return true
	}
	for _, s := range strings.Split(strings.ToLower(suffixes), ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if h == strings.TrimPrefix(s, ".") || strings.HasSuffix(h, s) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return true
		}
		for _, s := range strings.Split(ips, ",") {
			if o := net.ParseIP(strings.TrimSpace(s)); o != nil && o.Equal(ip) {
				return true
			}
		}
	}
	return false
}

type splitInfo struct {
	host string
	at   time.Time
}

type hostSeen struct {
	First int64 `json:"f"`
	Last  int64 `json:"l"`
}

type guard struct {
	members map[string]map[string]string // channel -> lower nick -> host ("" if unknown)
	known   map[string]*hostSeen         // lower host -> first/last seen in a monitored channel
	split   map[string]splitInfo         // lower nick -> netsplit QUIT record

	connectedAt  time.Time
	netjoinUntil time.Time

	klineTimes   []time.Time
	breakerUntil time.Time

	path       string
	dirty      bool
	lastSaved  time.Time
	infraSufx  string
	infraIPs   string
	warmup     time.Duration
	netjoinWin time.Duration
	splitTTL   time.Duration
	knownAfter time.Duration
	knownTTL   time.Duration
	maxKlines  int
	breakerFor time.Duration
}

func newGuard(path string) *guard {
	g := &guard{
		path:       path,
		known:      make(map[string]*hostSeen),
		infraSufx:  getenv("SENTRY_INFRA_SUFFIXES", ".chatnet.gg"),
		infraIPs:   getenv("SENTRY_INFRA_IPS", ""),
		warmup:     time.Duration(getenvInt("SENTRY_WARMUP_SEC", 300)) * time.Second,
		netjoinWin: time.Duration(getenvInt("SENTRY_NETJOIN_WINDOW_SEC", 90)) * time.Second,
		splitTTL:   time.Duration(getenvInt("SENTRY_SPLIT_TTL_MIN", 360)) * time.Minute,
		knownAfter: time.Duration(getenvInt("SENTRY_KNOWN_AFTER_SEC", 600)) * time.Second,
		knownTTL:   time.Duration(getenvInt("SENTRY_KNOWN_TTL_DAYS", 30)) * 24 * time.Hour,
		maxKlines:  getenvInt("SENTRY_MAX_KLINES_10MIN", 10),
		breakerFor: time.Duration(getenvInt("SENTRY_BREAKER_PAUSE_MIN", 30)) * time.Minute,
	}
	g.reset(time.Now())
	g.load()
	return g
}

// reset forgets live state (membership, split records) on every
// (re)connect; the persisted known-host set and breaker survive.
func (g *guard) reset(now time.Time) {
	g.members = make(map[string]map[string]string)
	g.split = make(map[string]splitInfo)
	g.connectedAt = now
	g.netjoinUntil = time.Time{}
}

func (g *guard) load() {
	if g.path == "" {
		return
	}
	data, err := os.ReadFile(g.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("guard: failed reading %s: %v", g.path, err)
		}
		return
	}
	m := make(map[string]*hostSeen)
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("guard: failed parsing %s: %v", g.path, err)
		return
	}
	cut := time.Now().Add(-g.knownTTL).Unix()
	for h, s := range m {
		if s != nil && s.Last >= cut {
			g.known[h] = s
		}
	}
	log.Printf("guard: loaded %d known hosts from %s", len(g.known), g.path)
}

func (g *guard) maybeSave(now time.Time) {
	if g.path == "" || !g.dirty || now.Sub(g.lastSaved) < time.Minute {
		return
	}
	cut := now.Add(-g.knownTTL).Unix()
	for h, s := range g.known {
		if s.Last < cut {
			delete(g.known, h)
		}
	}
	data, err := json.Marshal(g.known)
	if err != nil {
		return
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Printf("guard: save failed: %v", err)
		return
	}
	if err := os.Rename(tmp, g.path); err != nil {
		log.Printf("guard: save failed: %v", err)
		return
	}
	g.dirty = false
	g.lastSaved = now
}

func (g *guard) markKnown(host string, now time.Time, established bool) {
	h := strings.ToLower(host)
	if h == "" {
		return
	}
	s, ok := g.known[h]
	if !ok {
		first := now.Unix()
		if established {
			// present before we got here (NAMES): treat as long-standing
			first = now.Add(-g.knownAfter - time.Minute).Unix()
		}
		g.known[h] = &hostSeen{First: first, Last: now.Unix()}
		g.dirty = true
		return
	}
	if now.Unix()-s.Last > 60 {
		g.dirty = true
	}
	s.Last = now.Unix()
}

// isKnown: seen in a monitored channel at least knownAfter ago -- NOT
// merely "seen a moment ago", or the 2nd..200th clone from one host would
// look known right after the first.
func (g *guard) isKnown(host string, now time.Time) bool {
	s, ok := g.known[strings.ToLower(host)]
	return ok && now.Sub(time.Unix(s.First, 0)) >= g.knownAfter
}

func (g *guard) isMember(ch, nick string) bool {
	m := g.members[strings.ToLower(ch)]
	if m == nil {
		return false
	}
	_, ok := m[strings.ToLower(nick)]
	return ok
}

func (g *guard) addMember(ch, nick, host string) {
	c := strings.ToLower(ch)
	if g.members[c] == nil {
		g.members[c] = make(map[string]string)
	}
	g.members[c][strings.ToLower(nick)] = host
}

func (g *guard) removeMember(ch, nick string) {
	if m := g.members[strings.ToLower(ch)]; m != nil {
		delete(m, strings.ToLower(nick))
	}
}

func (g *guard) renameMember(oldNick, newNick string) {
	o, n := strings.ToLower(oldNick), strings.ToLower(newNick)
	for _, m := range g.members {
		if h, ok := m[o]; ok {
			delete(m, o)
			m[n] = h
		}
	}
}

func (g *guard) forgetChannel(ch string) { delete(g.members, strings.ToLower(ch)) }

// onNames records a 353 reply. With userhost-in-names entries look like
// "@nick!user@host"; without it they are bare nicks (host unknown).
func (g *guard) onNames(ch, names string, now time.Time) {
	for _, e := range strings.Fields(names) {
		e = strings.TrimLeft(e, "~&@%+")
		nick, host := e, ""
		if bang := strings.IndexByte(e, '!'); bang != -1 {
			nick = e[:bang]
			if at := strings.LastIndexByte(e, '@'); at > bang {
				host = e[at+1:]
			}
		}
		if nick == "" {
			continue
		}
		g.addMember(ch, nick, host)
		if host != "" {
			g.markKnown(host, now, true)
		}
	}
}

// onQuit removes nick everywhere and, for a netsplit QUIT, remembers it so
// the later JOIN is recognised as a netjoin. Returns true if it was a
// split quit of someone we had seen in a monitored channel.
func (g *guard) onQuit(nick, host, reason string, now time.Time) bool {
	l := strings.ToLower(nick)
	was := false
	for _, m := range g.members {
		if _, ok := m[l]; ok {
			delete(m, l)
			was = true
		}
	}
	if was && isSplitReason(reason) {
		g.split[l] = splitInfo{host: host, at: now}
		return true
	}
	return false
}

// inSplit reports whether a netsplit, a netjoin or the warm-up after a
// (re)connect is probably in progress, so nobody must be actioned.
func (g *guard) inSplit(now time.Time) bool {
	return now.Before(g.netjoinUntil) || now.Sub(g.connectedAt) < g.warmup
}

// classifyJoin updates presence for a JOIN into a monitored channel and
// returns "" if it should count toward the mass-join window, or the reason
// it must not.
func (g *guard) classifyJoin(ch, nick, host string, now time.Time) string {
	defer g.maybeSave(now)
	lower := strings.ToLower(nick)

	already := g.isMember(ch, nick)
	reason := ""
	switch {
	case already:
		reason = "already in channel"
	case func() bool {
		si, ok := g.split[lower]
		if ok && now.Sub(si.at) < g.splitTTL {
			delete(g.split, lower)
			g.netjoinUntil = now.Add(g.netjoinWin)
			return true
		}
		return false
	}():
		reason = "netsplit rejoin"
	case isInfraHost(host, g.infraSufx, g.infraIPs):
		reason = "ChatNet infrastructure"
	case now.Before(g.netjoinUntil):
		reason = "during netjoin"
	case g.isKnown(host, now):
		reason = "known host"
	case now.Sub(g.connectedAt) < g.warmup:
		reason = "warm-up after (re)connect"
	}

	g.addMember(ch, nick, host)
	g.markKnown(host, now, false)
	return reason
}

// allowKline is the circuit breaker: at most maxKlines per 10 minutes,
// then automatic K-lines pause for breakerFor.
func (g *guard) allowKline(now time.Time) bool {
	if now.Before(g.breakerUntil) {
		return false
	}
	cut := now.Add(-10 * time.Minute)
	kept := g.klineTimes[:0]
	for _, t := range g.klineTimes {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	g.klineTimes = kept
	if len(g.klineTimes) >= g.maxKlines {
		g.breakerUntil = now.Add(g.breakerFor)
		log.Printf("BREAKER TRIPPED: %d K-lines in 10 min (cap %d) -- automatic K-lines paused until %s",
			len(g.klineTimes), g.maxKlines, g.breakerUntil.Format(time.RFC3339))
		return false
	}
	g.klineTimes = append(g.klineTimes, now)
	return true
}
