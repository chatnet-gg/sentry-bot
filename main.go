// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
//
// Sentry -- ChatNet's own anti-abuse bot, replacing Ozone/Sigyn
// (github.com/Libera-Chat/ozone), which was removed 2026-08-17 after
// live testing showed its flood/repeat detection never actually fired
// (see project memory: project_bots_sasl_prereg_migration's "UPDATE"
// section, and project_custom_antiabuse_bot). Same hand-rolled IRC
// client pattern as cncheck-bot/znc-bot elsewhere in this project (no
// IRC library exists anywhere here) -- small enough that owning the
// whole detection pipeline directly is easier to reason about and test
// than debugging a third-party plugin written for a different ircd's
// snomask scheme.
//
// Detects four patterns directly from channel state this bot already
// sees as an ordinary member (no oper snomask needed for detection --
// only the KLINE itself needs oper):
//   - message flood: too many PRIVMSGs from one nick in a short window
//   - repeated message: the same line repeated back-to-back
//   - mass-join: too many JOINs into the channel in a short window
//     (classic clone-army pattern)
//   - join/part flood: one nick cycling JOIN+PART rapidly. Deliberately
//     a HIGH threshold -- ordinary client reconnect blips look like a
//     single join/part pair, this is only meant to catch someone
//     actually cycling repeatedly.
//
// On a hit: KLINE *@<host> directly (this bot's own ircd operator{}
// privset "abuse-bot" already grants oper:kline/oper:unkline -- see
// solanum/ircd.conf.template), which also drops the matching
// already-connected client as a side effect on solanum. Staff (cloaked
// chatnet/staff/*, configurable via SENTRY_STAFF_EXEMPT_PATTERN) are
// exempt -- see action()'s own comment.
//
// JOIN/PART/CHANNELS added 2026-08-17 -- IRC has
// no way to see a channel's traffic without actually being a member
// (true for everyone, including opers -- checked solanum's OJOIN
// extension too, it's not silent either), so extending coverage beyond
// the one channel set at startup needs this bot to actually join more
// channels, on demand. WHOIS-gated to one of AdminAccounts, same PM-only
// pattern as cncheck-bot's ADDOPER/ADDLINK (see that file's own header
// comment for the full reasoning). Channels added this way are
// in-memory only -- lost on a restart/reconnect, back to just the
// configured SENTRY_MAIN_CHANNEL. Not persisted to env/disk on purpose,
// to keep this bot's config surface small; re-run JOIN after a restart
// if that ever matters.
package main

import (
	"bufio"
	"errors"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Matches RPL_WHOISHOST's (378) trailing text: "is connecting from
// <ident>@<realhost> <ip>" -- see dispatch()'s "378" case.
var whoisHostRe = regexp.MustCompile(`is connecting from \S+@(\S+)`)

type Config struct {
	Server           string
	Port             string
	Nick             string
	NickservAccount  string
	NickservPassword string
	OperNick         string
	OperPassword     string
	MainChannel      string
	AdminAccounts    []string
	// Accounts allowed to arm KLINE on a channel (KLINE <#chan> ON).
	// Defaults to AdminAccounts; WHOIS-verified like every command.
	KlineAccounts   []string
	KlineArmMinutes int    // default and maximum arm duration, minutes (default 1 day)
	AlertTarget     string // nick or channel that gets NOTICEs about blocked/armed actions
	StaffExemptPattern string
	// Channels joined and monitored on every (re)connect. KLINE stays
	// disarmed everywhere until a person arms it, so being present is harmless.
	AutoJoinChannels   []string
	AutoJoin           bool // join+monitor MainChannel on connect; default OFF, an admin turns it on from IRC (JOIN)

	FloodPermit    int
	FloodWindow    time.Duration
	MassJoinPermit int
	MassJoinWindow time.Duration
	RepeatPermit   int
	RepeatWindow   time.Duration
	JoinPartPermit int
	JoinPartWindow time.Duration

	KlineDurationMin int
	KlineMessage     string
	ActionCooldown   time.Duration

	MinChannelSize int

	StateFile string
}

func loadConfig() Config {
	return Config{
		Server:           getenv("IRC_SERVER", "irc.chatnet.gg"),
		Port:             getenv("IRC_PORT", "6697"),
		Nick:             getenv("SENTRY_NICK", "Sentry"),
		NickservAccount:  getenv("SENTRY_NICKSERV_ACCOUNT", "sentry"),
		NickservPassword: mustEnv("SENTRY_NICKSERV_PASSWORD"),
		OperNick:         getenv("SENTRY_OPER_NICK", "sentry"),
		OperPassword:     mustEnv("SENTRY_OPER_PASSWORD"),
		MainChannel:      getenv("SENTRY_MAIN_CHANNEL", "#chatnet"),
		// Comma-separated NickServ accounts, any of which can use the
		// admin-only commands. Still WHOIS-verified per account, same as
		// a single admin -- see isAdmin().
		AdminAccounts: splitCommaList(getenv("SENTRY_ADMIN_ACCOUNTS", "abcX")),
		KlineAccounts:   splitCommaList(getenv("SENTRY_KLINE_ACCOUNTS", "")),
		KlineArmMinutes: getenvInt("SENTRY_KLINE_ARM_MINUTES", 1440),
		AlertTarget:     getenv("SENTRY_ALERT_TARGET", ""),
		// Comma-separated host prefixes (e.g. "chatnet/staff"); stored without
		// the "*@" and trailing "*" of a full mask, which are implicit in the
		// prefix match done by exemptPrefix().
		StaffExemptPattern: getenv("SENTRY_STAFF_EXEMPT_PATTERN", "chatnet/staff,chatnet/service/,chatnet/bot/"),
		AutoJoin:           getenv("SENTRY_AUTOJOIN", "") == "1",
		AutoJoinChannels:   splitCommaList(getenv("SENTRY_AUTOJOIN_CHANNELS", "")),

		FloodPermit:    getenvInt("SENTRY_FLOOD_PERMIT", 30),
		FloodWindow:    time.Duration(getenvInt("SENTRY_FLOOD_WINDOW_SEC", 40)) * time.Second,
		// Raised 2026-08-18 -- same "stay high, avoid accidental klines"
		// philosophy as flood/join-part above. Was 6/10s and 4/30s.
		MassJoinPermit: getenvInt("SENTRY_MASSJOIN_PERMIT", 15),
		MassJoinWindow: time.Duration(getenvInt("SENTRY_MASSJOIN_WINDOW_SEC", 15)) * time.Second,
		RepeatPermit:   getenvInt("SENTRY_REPEAT_PERMIT", 15),
		RepeatWindow:   time.Duration(getenvInt("SENTRY_REPEAT_WINDOW_SEC", 30)) * time.Second,
		// High on purpose -- staying conservative here avoids
		// accidentally klining legitimate users; a normal client
		// reconnect blip is one join+part pair, this only fires on
		// someone actually cycling repeatedly.
		JoinPartPermit: getenvInt("SENTRY_JOINPART_PERMIT", 10),
		JoinPartWindow: time.Duration(getenvInt("SENTRY_JOINPART_WINDOW_SEC", 20)) * time.Second,

		KlineDurationMin: getenvInt("SENTRY_KLINE_MINUTES", 1440), // 1 day
		KlineMessage:     getenv("SENTRY_KLINE_MESSAGE", "Automatic anti-spam ban (flood/repeat detection). If this is a mistake, contact abcx@chatnet.gg to appeal."),
		ActionCooldown:   30 * time.Second,

		MinChannelSize: getenvInt("SENTRY_MIN_CHANNEL_SIZE", 10),

		StateFile: getenv("SENTRY_STATE_FILE", "/data/settings.json"),
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid int for %s: %q", key, v)
	}
	return n
}

func splitCommaList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// canKline: may this account arm KLINE? Admins always, plus KlineAccounts.
func (cfg Config) canKline(account string) bool {
	if cfg.isAdmin(account) {
		return true
	}
	for _, a := range cfg.KlineAccounts {
		if strings.EqualFold(a, account) {
			return true
		}
	}
	return false
}

func (cfg Config) isAdmin(account string) bool {
	for _, a := range cfg.AdminAccounts {
		if strings.EqualFold(a, account) {
			return true
		}
	}
	return false
}

// joinEvent is one JOIN into a monitored channel, kept with its nick and
// cloaked host (not just a timestamp) so recordJoin can action EVERY
// nick in a triggering burst, not just whichever one crossed the
// threshold -- see recordJoin's own comment.
type joinEvent struct {
	at   time.Time
	nick string
	host string
}

// nickState tracks the sliding-window detection state for one nick.
type nickState struct {
	msgTimes      []time.Time
	lastText      string
	repeatSince   time.Time
	repeatCount   int
	joinPartTimes []time.Time
	lastHost      string // cloaked host, from this nick's own PRIVMSG/JOIN prefix -- fallback only, see pendingKline's own comment
	lastAction    time.Time
}

// pendingKline tracks a WHOIS this bot sent to resolve a target's REAL
// host before actually issuing a KLINE -- see action()'s own comment for
// why a cloaked host is useless as a ban mask.
type pendingKline struct {
	nick      string
	reason    string
	fallback  string // the cloaked host, used only if 378 never arrives
	channel   string // where it was detected; KLINE must still be armed there when it is issued
	createdAt time.Time
}

// pendingChanCmd is the WHOIS-verified-as-admin gate for
// JOIN/PART/CHANNELS/APPROVE/DENY -- same shape as cncheck-bot's own
// pendingOperCmd (see that file for the pattern this is copied from).
type pendingChanCmd struct {
	nick      string
	kind      string // "JOIN", "PART", "CHANNELS", "APPROVE", "DENY", "SET", "SETTINGS", "CHANSET", "CHANSETTINGS", "CHANRESET"
	channel   string
	account   string
	// SET/CHANSET/CHANRESET only -- reuses the struct rather than adding
	// a whole parallel pending type for a few more commands. CHANRESET
	// only ever uses setKey (a key name, or "ALL"), never setValue.
	setKey   string
	setValue string
	createdAt time.Time
}

// pendingSizeCheck tracks a NAMES this bot sent to check a REQUESTed
// channel's member count against MinChannelSize before ever bothering
// the admin with it -- see handleRequest's own comment.
type pendingSizeCheck struct {
	nick      string
	channel   string
	count     int
	createdAt time.Time
}

type Bot struct {
	cfg     Config
	conn    net.Conn
	nicks   map[string]*nickState
	joins   map[string][]joinEvent // per-channel mass-join sliding windows
	sendHook   func(string) // tests only: sees every line sent
	// One-time "you may arm KLINE" private message to each KLINE account,
	// retried every 10 min until delivered (no 401), remembered on disk so
	// a restart never messages anyone twice.
	notifyReady time.Time
	lastNotify  time.Time
	notifySent  map[string]time.Time
	notifyDone  map[string]bool
	klineArmed map[string]time.Time // lower-case channel -> expiry of the KLINE arm; never persisted, a restart disarms everything
	lastAlert  map[string]time.Time
	klineQueue []*pendingKline // FIFO -- see action()/finishPendingKline's own comments

	channels   map[string]bool // currently-monitored channels
	pendingCmd *pendingChanCmd
	pendingReq *pendingSizeCheck
	// channel -> nick who sent REQUEST for it, until an admin
	// APPROVEs/DENYs -- see REQUEST's own comment.
	pendingRequests map[string]string

	// channel -> setting key -> value, only ever the 8 detection-
	// threshold keys in validChannelSettingKeys -- see
	// effectiveConfig for how this layers on top of b.cfg. Unlike
	// b.channels above, this is NOT reset on reconnect (it's persisted
	// settings data, loaded once at startup, not live channel
	// membership) -- a channel's tuned thresholds should still apply
	// the next time it's JOINed, even across a bot restart.
	channelOverrides map[string]map[string]string

	saslDone bool

	guard *guard // netsplit/presence/infra guards, see guard.go
}

func main() {
	cfg := loadConfig()
	channelOverrides := loadSavedSettings(&cfg)
	b := &Bot{cfg: cfg, nicks: make(map[string]*nickState), channelOverrides: channelOverrides,
		klineArmed: make(map[string]time.Time), lastAlert: make(map[string]time.Time),
		notifySent: make(map[string]time.Time), notifyDone: make(map[string]bool)}
	b.loadNotified()
	b.guard = newGuard(getenv("SENTRY_KNOWN_FILE", filepath.Join(filepath.Dir(cfg.StateFile), "known-hosts.json")))

	backoff := time.Second
	for {
		if err := b.connectAndRun(); err != nil {
			log.Printf("connection error: %v (reconnecting in %s)", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 60*time.Second {
			backoff *= 2
		} else {
			backoff = 60 * time.Second
		}
	}
}

func (b *Bot) connectAndRun() error {
	addr := net.JoinHostPort(b.cfg.Server, b.cfg.Port)
	rawConn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	// Self-signed cert, bare docker-internal IP, same trust model as
	// znc-bot's own internal-only connection to the bouncer -- this stays
	// entirely on the internal docker network, never touches the public
	// internet, so there's no real CA to verify against anyway.
	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()
	b.conn = tlsConn
	b.nicks = make(map[string]*nickState)
	b.joins = make(map[string][]joinEvent)
	b.klineQueue = nil
	b.pendingCmd = nil
	b.pendingReq = nil
	b.pendingRequests = make(map[string]string)
	// Reset to just the configured main channel on every (re)connect --
	// extra channels added via JOIN/APPROVE are deliberately in-memory
	// only, see this file's own top comment.
	b.channels = map[string]bool{}
	if b.cfg.AutoJoin {
		b.channels[b.cfg.MainChannel] = true
	}
	for _, c := range b.cfg.AutoJoinChannels {
		if channelNameRe.MatchString(c) {
			b.channels[c] = true
		}
	}
	b.guard.reset(time.Now())
	b.saslDone = false

	// SASL PLAIN, pre-registration -- see project memory
	// project_bots_sasl_prereg_migration for why (avoids the CHGHOST
	// blip a post-connect NickServ IDENTIFY causes). No client cert here
	// -- PLAIN alone is enough and this project already stores every
	// bot's NickServ password in plaintext env vars anyway (same trust
	// tier), no need for EXTERNAL's extra complexity on a brand new bot.
	b.send("CAP LS 302")
	b.send("NICK " + b.cfg.Nick)
	b.send("USER " + b.cfg.Nick + " 0 * :ChatNet anti-abuse bot")
	log.Printf("connecting to %s as %s", addr, b.cfg.Nick)

	return readLines(tlsConn, 5*time.Second,
		func(line string) { b.dispatch(parseLine(line)) },
		func() { b.checkQueueTimeout(); b.tickNotify(time.Now()) }) // timers must not depend on incoming traffic
}

// readLines reads IRC lines from conn, calling onLine for each. Every idle
// period without data it calls onIdle, so time-based work (the queued-KLINE
// timeout) runs even when the server is silent. A line split across an idle
// timeout is kept, not dropped.
func readLines(conn net.Conn, idle time.Duration, onLine func(string), onIdle func()) error {
	reader := bufio.NewReader(conn)
	partial := ""
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		chunk, err := reader.ReadString('\n')
		partial += chunk
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				onIdle()
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		line := strings.TrimRight(partial, "\r\n")
		partial = ""
		if line != "" {
			onLine(line)
		}
	}
}

func (b *Bot) send(s string) {
	if b.sendHook != nil {
		b.sendHook(s)
	}
	if b.conn == nil {
		return
	}
	b.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(b.conn, "%s\r\n", s)
}

func saslPlainPayload(account, password string) string {
	raw := account + "\x00" + account + "\x00" + password
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func (b *Bot) dispatch(l Line) {
	b.checkQueueTimeout()
	b.tickNotify(time.Now())

	switch l.Command {
	case "PING":
		b.send("PONG :" + l.Trailing)

	case "CAP":
		if len(l.Params) < 2 {
			break
		}
		switch strings.ToUpper(l.Params[1]) {
		case "LS":
			var want []string
			for _, c := range []string{"sasl", "userhost-in-names"} {
				if strings.Contains(l.Trailing, c) {
					want = append(want, c)
				}
			}
			if len(want) > 0 {
				b.send("CAP REQ :" + strings.Join(want, " "))
			} else {
				b.send("CAP END")
			}
		case "ACK":
			if strings.Contains(l.Trailing, "sasl") {
				b.send("AUTHENTICATE PLAIN")
			} else {
				b.send("CAP END")
			}
		case "NAK":
			b.send("CAP END")
		}

	case "AUTHENTICATE":
		if len(l.Params) > 0 && l.Params[0] == "+" {
			b.send("AUTHENTICATE " + saslPlainPayload(b.cfg.NickservAccount, b.cfg.NickservPassword))
		}

	case "903": // RPL_SASLSUCCESS
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "904", "905", "906", "907": // SASL failure
		log.Printf("SASL failed (%s: %s) -- connecting unauthenticated", l.Command, l.Trailing)
		if !b.saslDone {
			b.saslDone = true
			b.send("CAP END")
		}

	case "001":
		b.notifyReady = time.Now().Add(45 * time.Second)
		b.send(fmt.Sprintf("OPER %s %s", b.cfg.OperNick, b.cfg.OperPassword))
		for _, c := range b.cfg.AutoJoinChannels {
			if channelNameRe.MatchString(c) && !(b.cfg.AutoJoin && strings.EqualFold(c, b.cfg.MainChannel)) {
				b.send("JOIN " + c)
				log.Printf("auto-joined %s (SENTRY_AUTOJOIN_CHANNELS), KLINE disarmed until a person arms it", c)
			}
		}
		if b.cfg.AutoJoin {
			b.send("JOIN " + b.cfg.MainChannel)
			log.Printf("registered, joined %s, opering up as %s", b.cfg.MainChannel, b.cfg.OperNick)
		} else {
			log.Printf("registered, opering up as %s; monitoring is OFF until an admin sends JOIN <#channel>", b.cfg.OperNick)
		}

	case "401": // ERR_NOSUCHNICK: an access notice did not reach anyone, retry later
		if len(l.Params) >= 2 {
			delete(b.notifySent, strings.ToLower(l.Params[1]))
		}

	case "381": // RPL_YOUREOPER
		log.Printf("oper-up succeeded")

	case "464":
		log.Printf("oper-up FAILED (password mismatch) -- KLINE won't work until this is fixed")

	case "378": // RPL_WHOISHOST (auspex:hostname-gated real host/IP reveal)
		// "<nick> :is connecting from <ident>@<realhost> <ip>" -- see
		// action()'s own comment for why this exists at all. Only ever
		// the QUEUE HEAD has an outstanding WHOIS (see action()), so
		// that's the only entry this can ever legitimately resolve.
		if len(b.klineQueue) > 0 && len(l.Params) >= 2 && strings.EqualFold(l.Params[1], b.klineQueue[0].nick) {
			if m := whoisHostRe.FindStringSubmatch(l.Trailing); m != nil {
				b.finishPendingKline(m[1])
			}
		}

	case "330": // RPL_WHOISACCOUNT: <me> <nick> <account> :is logged in as
		if b.pendingCmd != nil && len(l.Params) >= 3 && strings.EqualFold(l.Params[1], b.pendingCmd.nick) {
			b.pendingCmd.account = l.Params[2]
		}

	case "318": // RPL_ENDOFWHOIS
		// Fallback if 378 never arrived (nick already gone, or somehow
		// not oper-visible) -- better to kline the stale cloaked host
		// than to silently do nothing.
		if len(b.klineQueue) > 0 && len(l.Params) >= 2 && strings.EqualFold(l.Params[1], b.klineQueue[0].nick) {
			b.finishPendingKline(b.klineQueue[0].fallback)
			break
		}
		if b.pendingCmd != nil && len(l.Params) >= 2 && strings.EqualFold(l.Params[1], b.pendingCmd.nick) {
			b.finishPendingCmd()
		}

	case "353": // RPL_NAMREPLY (counting members for a pending REQUEST size check)
		if b.pendingReq != nil && len(l.Params) >= 3 && strings.EqualFold(l.Params[2], b.pendingReq.channel) {
			b.pendingReq.count += len(strings.Fields(l.Trailing))
		}
		if len(l.Params) >= 3 && b.channels[l.Params[2]] {
			b.guard.onNames(l.Params[2], l.Trailing, time.Now())
		}

	case "366": // RPL_ENDOFNAMES
		if b.pendingReq != nil && len(l.Params) >= 2 && strings.EqualFold(l.Params[1], b.pendingReq.channel) {
			b.finishPendingRequest()
		}

	case "JOIN":
		if b.channels[l.target()] {
			b.recordJoin(l)
			b.recordJoinPartCycle(l.Nick, l.Host, l.target())
		}

	case "PART":
		if b.channels[l.target()] {
			b.recordJoinPartCycle(l.Nick, l.Host, l.target())
			b.guard.removeMember(l.target(), l.Nick)
		}

	case "KICK":
		if b.channels[l.target()] && len(l.Params) >= 2 {
			b.guard.removeMember(l.target(), l.Params[1])
		}

	case "NICK":
		newNick := l.Trailing
		if newNick == "" && len(l.Params) > 0 {
			newNick = l.Params[0]
		}
		if newNick != "" {
			b.guard.renameMember(l.Nick, newNick)
		}

	case "QUIT":
		if b.guard.onQuit(l.Nick, l.Host, l.Trailing, time.Now()) {
			log.Printf("netsplit QUIT: %s (%s)", l.Nick, l.Trailing)
		}

	case "PRIVMSG":
		if b.channels[l.target()] {
			b.recordMessage(l)
		} else if strings.EqualFold(l.target(), b.cfg.Nick) {
			b.handlePrivate(l.Nick, l.text())
		}
	}
}

func (b *Bot) getState(nick string) *nickState {
	st, ok := b.nicks[nick]
	if !ok {
		st = &nickState{}
		b.nicks[nick] = st
	}
	return st
}

// recordJoin tracks per-channel join bursts for the mass-join check.
// Used to only action the ONE join that happened to cross the threshold -- so a
// coordinated 100-IP join burst would leave 99 of them sitting in the
// channel un-actioned. Now actions EVERY nick that joined within the
// triggering window, not just the last one -- each goes through
// action()'s own dedup+queue (see its comment), so a big burst queues
// up and drains via the WHOIS queue instead of mostly being ignored.
func (b *Bot) recordJoin(l Line) {
	chan_ := l.target()
	if strings.EqualFold(l.Nick, b.cfg.Nick) {
		return
	}
	if why := b.guard.classifyJoin(chan_, l.Nick, l.Host, time.Now()); why != "" {
		log.Printf("JOIN %s %s (%s): not counted toward mass-join -- %s", chan_, l.Nick, l.Host, why)
		return
	}
	ec := b.effectiveConfig(chan_)
	now := time.Now()
	events := append(b.joins[chan_], joinEvent{at: now, nick: l.Nick, host: l.Host})
	cutoff := now.Add(-ec.MassJoinWindow)
	pruned := events[:0]
	for _, e := range events {
		if e.at.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	b.joins[chan_] = pruned

	if len(pruned) > ec.MassJoinPermit {
		log.Printf("MASSJOIN in %s: %d joins in %s (permit %d), actioning all %d",
			chan_, len(pruned), ec.MassJoinWindow, ec.MassJoinPermit, len(pruned))
		for _, e := range pruned {
			b.action(e.nick, e.host, "mass-join detected in "+chan_, chan_)
		}
		b.joins[chan_] = nil
	}
}

// recordJoinPartCycle tracks one nick's own JOIN+PART events (any
// monitored channel) for the join/part-flood check -- separate from
// recordJoin's mass-join tracking above, which is about MANY nicks
// joining one channel, not ONE nick cycling repeatedly. channel is the
// triggering JOIN/PART's own channel, used only to resolve which
// per-channel threshold override applies (2026-08-18) -- a nick's
// cycle count itself is still tracked across all monitored channels
// combined, only the permit/window compared against it varies.
func (b *Bot) recordJoinPartCycle(nick, host, channel string) {
	if nick == "" || host == "" {
		return
	}
	ec := b.effectiveConfig(channel)
	now := time.Now()
	st := b.getState(nick)
	st.lastHost = host
	st.joinPartTimes = append(st.joinPartTimes, now)
	cutoff := now.Add(-ec.JoinPartWindow)
	pruned := st.joinPartTimes[:0]
	for _, t := range st.joinPartTimes {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	st.joinPartTimes = pruned

	if len(pruned) > ec.JoinPartPermit {
		log.Printf("JOINPART: %s cycled %d join/part events in %s (permit %d)",
			nick, len(pruned), ec.JoinPartWindow, ec.JoinPartPermit)
		b.action(nick, host, "join/part flood detected", channel)
		st.joinPartTimes = nil
	}
}

func (b *Bot) recordMessage(l Line) {
	if l.Nick == "" || l.Host == "" {
		return
	}
	ec := b.effectiveConfig(l.target())
	now := time.Now()
	st := b.getState(l.Nick)
	st.lastHost = l.Host

	// Flood: sliding window of message timestamps.
	st.msgTimes = append(st.msgTimes, now)
	cutoff := now.Add(-ec.FloodWindow)
	pruned := st.msgTimes[:0]
	for _, t := range st.msgTimes {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	st.msgTimes = pruned

	if len(st.msgTimes) > ec.FloodPermit {
		log.Printf("FLOOD: %s sent %d lines in %s (permit %d)", l.Nick, len(st.msgTimes), ec.FloodWindow, ec.FloodPermit)
		b.action(l.Nick, l.Host, "message flood detected", l.target())
		st.msgTimes = nil
		st.repeatCount = 0
		return
	}

	// Repeat: same line back-to-back, reset if the window elapses or the
	// text changes.
	text := l.text()
	if text == st.lastText && now.Sub(st.repeatSince) <= ec.RepeatWindow {
		st.repeatCount++
	} else {
		st.lastText = text
		st.repeatSince = now
		st.repeatCount = 1
	}

	if st.repeatCount >= ec.RepeatPermit {
		log.Printf("REPEAT: %s repeated the same line %d times in %s", l.Nick, st.repeatCount, ec.RepeatWindow)
		b.action(l.Nick, l.Host, "repeated message detected", l.target())
		st.repeatCount = 0
	}
}

// action starts the KLINE process for a detected violation, with a short
// per-nick cooldown so a burst of messages that all cross a threshold
// within the same instant doesn't fire several redundant WHOIS/KLINE
// attempts for the same nick before the first one completes.
//
// It does NOT kline `host` directly -- that's the CLOAKED host, taken
// from the offending PRIVMSG/JOIN's own prefix, which is what every
// other client (including this bot) sees. Cloaks intentionally hide the
// real host from everyone, this bot included, so a mask built from one
// would almost never match the actual abuser's real connection (found
// live, 2026-08-17: a KLINE against a cloaked host was silently a no-op
// -- confirmed by successfully reconnecting from the exact same box
// right after). Real fix: WHOIS the target first -- RPL_WHOISHOST (378)
// reveals the true host/IP, but only to opers with the auspex:hostname
// privilege (added to this bot's own "abuse-bot" privset for exactly
// this). See dispatch()'s "378"/"318" cases for the other half of this.
//
// Staff exemption: checked against the
// CLOAKED host, not the real one -- staff cloaks (chatnet/staff/*) are
// exactly the thing meant to be publicly recognizable as staff, unlike
// a regular user's cloak, which exists specifically to hide their real
// host. Checked first, before the cooldown/WHOIS machinery below, so a
// staffer never even costs this bot a WHOIS round-trip.
//
// This used to just drop the action outright if a
// WHOIS was already in flight for someone else -- fine for one lamer,
// useless against a real coordinated attack (100 different IPs joining
// at once would have gotten AT MOST one of them actually klined, the
// rest silently ignored). Now enqueues instead of dropping -- see
// klineQueue/processKlineQueue below, which processes every queued
// nick one at a time (each needs its own WHOIS round-trip to resolve a
// real host) instead of losing all but the first.
// exemptPrefix returns the entry of patterns (comma-separated host
// prefixes, e.g. "chatnet/staff,chatnet/service/") that host starts
// with, or "" if none. Services that print many lines at once (art or game services)
// by design, so their chatnet/service/* cloak is exempt alongside staff.
func exemptPrefix(host, patterns string) string {
	h := strings.ToLower(host)
	for _, p := range strings.Split(patterns, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && strings.HasPrefix(h, p) {
			return p
		}
	}
	return ""
}

// klineBlocked returns "" if an automatic network ban is allowed for a
// detection in channel, else why not. A KLINE only happens in a channel
// that a person armed with KLINE <#chan> ON, never during a probable
// netsplit, and never after the arm expired. Detections that are not
// allowed to ban are logged and alerted instead.
func (b *Bot) klineBlocked(channel string, now time.Time) string {
	until, ok := b.klineArmed[strings.ToLower(channel)]
	switch {
	case !ok:
		return "KLINE not armed for " + channel
	case !now.Before(until):
		delete(b.klineArmed, strings.ToLower(channel))
		return "KLINE arm for " + channel + " expired"
	case b.guard.inSplit(now):
		return "probable netsplit / warm-up"
	}
	return ""
}

// alert logs and, if SENTRY_ALERT_TARGET is set, sends a short NOTICE
// (at most one per key per minute).
func (b *Bot) alert(key, msg string) {
	log.Printf("ALERT: %s", msg)
	if b.cfg.AlertTarget == "" || time.Since(b.lastAlert[key]) < time.Minute {
		return
	}
	b.lastAlert[key] = time.Now()
	b.send(fmt.Sprintf("NOTICE %s :[Sentry] %s", b.cfg.AlertTarget, msg))
}

func (b *Bot) action(nick, host, reason, channel string) {
	if p := exemptPrefix(host, b.cfg.StaffExemptPattern); p != "" {
		log.Printf("EXEMPT: %s (%s) matched staff pattern %q, not actioning -- %s", nick, host, p, reason)
		return
	}

	if isInfraHost(host, b.guard.infraSufx, b.guard.infraIPs) {
		log.Printf("EXEMPT: %s (%s) is ChatNet infrastructure, not actioning -- %s", nick, host, reason)
		return
	}

	if why := b.klineBlocked(channel, time.Now()); why != "" {
		log.Printf("NO-KLINE (%s): %s (%s) -- %s", why, nick, host, reason)
		b.alert("blocked:"+strings.ToLower(channel), fmt.Sprintf("%s in %s: %s (%s) -- NOT banned (%s). A staff member can arm it: /msg Sentry KLINE %s ON", reason, channel, nick, host, why, channel))
		return
	}

	st := b.getState(nick)
	if time.Since(st.lastAction) < b.cfg.ActionCooldown {
		return
	}
	st.lastAction = time.Now()

	for _, q := range b.klineQueue {
		if strings.EqualFold(q.nick, nick) {
			// Already queued (e.g. flagged by two different checks at
			// once) -- don't duplicate, it'll be handled.
			return
		}
	}
	b.klineQueue = append(b.klineQueue, &pendingKline{nick: nick, reason: reason, fallback: host, channel: channel, createdAt: time.Now()})
	log.Printf("QUEUED kline for %s (%s) -- %s (queue depth now %d)", nick, host, reason, len(b.klineQueue))
	if len(b.klineQueue) == 1 {
		// Nothing else in flight -- start processing immediately. If the
		// queue was already non-empty, this new entry just waits its
		// turn; finishPendingKline advances the queue itself.
		b.send("WHOIS " + nick)
	}
}

// finishPendingKline completes whatever's at the head of klineQueue
// (dispatch's "378"/"318" cases only ever call this for the head nick,
// see their own checks), issues the real KLINE, pops it, and immediately
// starts the next queued WHOIS if there is one -- this is what makes a
// long queue under a real attack actually drain instead of stalling
// after the first entry.
func (b *Bot) finishPendingKline(host string) {
	if len(b.klineQueue) == 0 {
		return
	}
	p := b.klineQueue[0]
	b.klineQueue = b.klineQueue[1:]

	mask := "*@" + host
	switch {
	case b.klineBlocked(p.channel, time.Now()) != "":
		log.Printf("SKIP KLINE %s (%s): %s -- %s", mask, p.nick, b.klineBlocked(p.channel, time.Now()), p.reason)
	case isInfraHost(host, b.guard.infraSufx, b.guard.infraIPs):
		log.Printf("SKIP KLINE %s (%s): real host is ChatNet infrastructure -- %s", mask, p.nick, p.reason)
	case !b.guard.allowKline(time.Now()):
		log.Printf("SKIP KLINE %s (%s): circuit breaker open, dropping the %d queued -- %s", mask, p.nick, len(b.klineQueue), p.reason)
		b.klineQueue = nil
		return
	default:
		log.Printf("KLINE %s (%s) -- %s (queue depth now %d)", mask, p.nick, p.reason, len(b.klineQueue))
		b.send(fmt.Sprintf("KLINE %d %s :%s|%s", b.cfg.KlineDurationMin, mask, b.cfg.KlineMessage, p.reason))
	}

	if len(b.klineQueue) > 0 {
		b.send("WHOIS " + b.klineQueue[0].nick)
	}
}

// checkQueueTimeout is called once per dispatch() -- if the queue head's
// WHOIS has been outstanding unreasonably long (378/318 lost, nick quit
// mid-WHOIS on some ircds without a clean 318, etc), force it through on
// its cloaked fallback rather than let one bad entry stall the whole
// queue forever under a real attack. No ticker/goroutine needed for
// this -- checking on every line this bot already reads is frequent
// enough (many lines per second under any real load) and keeps
// everything on the single dispatch goroutine.
func (b *Bot) checkQueueTimeout() {
	if len(b.klineQueue) == 0 {
		return
	}
	if time.Since(b.klineQueue[0].createdAt) > 15*time.Second {
		log.Printf("WHOIS for queued kline on %s timed out, using fallback host", b.klineQueue[0].nick)
		b.finishPendingKline(b.klineQueue[0].fallback)
	}
}

var channelNameRe = regexp.MustCompile(`^#[^\s,:\x07]{1,49}$`)

func (b *Bot) handlePrivate(nick, text string) {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return
	}
	switch {
	case strings.EqualFold(fields[0], "JOIN"):
		b.startPendingCmd(nick, "JOIN", fields[1:])
	case strings.EqualFold(fields[0], "PART"):
		b.startPendingCmd(nick, "PART", fields[1:])
	case strings.EqualFold(fields[0], "CHANNELS"):
		b.startPendingCmd(nick, "CHANNELS", nil)
	case strings.EqualFold(fields[0], "APPROVE"):
		b.startPendingCmd(nick, "APPROVE", fields[1:])
	case strings.EqualFold(fields[0], "DENY"):
		b.startPendingCmd(nick, "DENY", fields[1:])
	case strings.EqualFold(fields[0], "KLINE"):
		b.handleKlineCmd(nick, fields[1:])
	case strings.EqualFold(fields[0], "REQUEST"):
		b.handleRequest(nick, fields[1:])
	case strings.EqualFold(fields[0], "SET"):
		b.handleSet(nick, fields[1:])
	case strings.EqualFold(fields[0], "SETTINGS"):
		b.startPendingCmd(nick, "SETTINGS", nil)
	case strings.EqualFold(fields[0], "CHANSET"):
		b.handleChanSet(nick, fields[1:])
	case strings.EqualFold(fields[0], "CHANSETTINGS"):
		b.startPendingCmd(nick, "CHANSETTINGS", fields[1:])
	case strings.EqualFold(fields[0], "CHANRESET"):
		b.handleChanReset(nick, fields[1:])
	case strings.EqualFold(fields[0], "HELP"):
		b.handleHelp(nick)
	}
}

// helpLines is public info, no WHOIS gate -- unlike every actual command
// above, there's nothing sensitive in just describing what they do.
var helpLines = []string{
	"Sentry -- ChatNet's anti-abuse bot. It is OFF by default: it watches a channel only after an admin sends JOIN <#channel>, and stops on PART. While watching, it checks for message flood, repeated messages, and mass-join (clone-army) patterns, and issues a temporary KLINE against the real offending host when one fires.",
	"Commands (all via /msg Sentry <command>):",
	"  REQUEST <#channel> -- ask Sentry to start monitoring a channel (needs 10+ members, then waits on admin approval). Anyone can use this.",
	"  HELP -- this message.",
	"Admin-only (WHOIS-verified):",
	"  JOIN <#channel> / PART <#channel> -- start/stop monitoring a channel immediately.",
	"  CHANNELS -- list channels currently being monitored.",
	"  KLINE <#channel> ON [minutes] / OFF / STATUS -- (admins and SENTRY_KLINE_ACCOUNTS) arm or disarm automatic KLINE for a channel, joining it if needed. Off by default, never persisted, expires by itself, paused during a probable netsplit. Without arming, detections only log and alert. KLINE alone lists the armed channels.",
	"  APPROVE <#channel> / DENY <#channel> -- resolve a pending REQUEST.",
	"  SETTINGS -- show current thresholds/durations.",
	"  SET <key> <value> -- change one live, no restart, persisted to disk (survives a restart). Keys: FLOOD_PERMIT, FLOOD_WINDOW, MASSJOIN_PERMIT, MASSJOIN_WINDOW, REPEAT_PERMIT, REPEAT_WINDOW, JOINPART_PERMIT, JOINPART_WINDOW, KLINE_MINUTES, KLINE_MESSAGE, MIN_CHANNEL_SIZE, STAFF_EXEMPT_PATTERN. WINDOW values are seconds.",
	"  CHANSETTINGS <#channel> -- show that channel's effective thresholds (global, with any per-channel override applied).",
	"  CHANSET <#channel> <key> <value> -- override one threshold for just that channel, persisted. Keys: FLOOD_PERMIT, FLOOD_WINDOW, MASSJOIN_PERMIT, MASSJOIN_WINDOW, REPEAT_PERMIT, REPEAT_WINDOW, JOINPART_PERMIT, JOINPART_WINDOW (same as SET, minus KLINE_*/STAFF_EXEMPT_PATTERN which stay global-only).",
	"  CHANRESET <#channel> <key-or-ALL> -- clear one (or every) per-channel override, falling back to the global value.",
}

func (b *Bot) handleHelp(nick string) {
	for _, line := range helpLines {
		b.send(fmt.Sprintf("NOTICE %s :%s", nick, line))
	}
}

// startPendingCmd is JOIN/PART/CHANNELS/APPROVE/DENY's shared
// WHOIS-verified-as-admin gate -- same pattern as cncheck-bot's
// own startPending (see that file for the full reasoning: real NickServ
// account read authoritatively off the ircd via WHOIS, not trusted from
// anything the sender said about themselves).
func (b *Bot) startPendingCmd(nick, kind string, args []string) {
	channel := ""
	if kind != "CHANNELS" && kind != "SETTINGS" {
		if len(args) != 1 {
			b.send(fmt.Sprintf("NOTICE %s :Syntax: %s <#channel>", nick, kind))
			return
		}
		if !channelNameRe.MatchString(args[0]) {
			b.send(fmt.Sprintf("NOTICE %s :Invalid channel name.", nick))
			return
		}
		channel = args[0]
	}
	if b.pendingCmd != nil && time.Since(b.pendingCmd.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pendingCmd = &pendingChanCmd{nick: nick, kind: kind, channel: channel, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

func (b *Bot) finishPendingCmd() {
	p := b.pendingCmd
	b.pendingCmd = nil

	if p.kind == "KLINE" {
		b.finishKlineCmd(p)
		return
	}
	if !b.cfg.isAdmin(p.account) {
		log.Printf("%s denied: %s is not one of %v (account seen: %q)", p.kind, p.nick, b.cfg.AdminAccounts, p.account)
		b.send(fmt.Sprintf("NOTICE %s :Do I know you?", p.nick))
		return
	}

	switch p.kind {
	case "JOIN":
		if b.channels[p.channel] {
			b.send(fmt.Sprintf("NOTICE %s :Already monitoring %s.", p.nick, p.channel))
			return
		}
		b.channels[p.channel] = true
		b.send("JOIN " + p.channel)
		log.Printf("JOIN %s requested by %s (account %s)", p.channel, p.nick, p.account)
		b.send(fmt.Sprintf("NOTICE %s :Joined and now monitoring %s.", p.nick, p.channel))

	case "PART":
		if !b.channels[p.channel] || (b.cfg.AutoJoin && strings.EqualFold(p.channel, b.cfg.MainChannel)) {
			b.send(fmt.Sprintf("NOTICE %s :Not monitoring %s (or it's the auto-joined main channel, won't part that one).", p.nick, p.channel))
			return
		}
		delete(b.channels, p.channel)
		delete(b.joins, p.channel)
		b.guard.forgetChannel(p.channel)
		b.send("PART " + p.channel)
		log.Printf("PART %s requested by %s (account %s)", p.channel, p.nick, p.account)
		b.send(fmt.Sprintf("NOTICE %s :Left and stopped monitoring %s.", p.nick, p.channel))

	case "CHANNELS":
		list := make([]string, 0, len(b.channels))
		for c := range b.channels {
			list = append(list, c)
		}
		sort.Strings(list)
		b.send(fmt.Sprintf("NOTICE %s :Monitoring: %s", p.nick, strings.Join(list, ", ")))

	case "APPROVE", "DENY":
		requester, ok := b.pendingRequests[p.channel]
		if !ok {
			b.send(fmt.Sprintf("NOTICE %s :No pending request for %s.", p.nick, p.channel))
			return
		}
		delete(b.pendingRequests, p.channel)
		if p.kind == "DENY" {
			log.Printf("REQUEST for %s (from %s) DENIED by %s", p.channel, requester, p.nick)
			b.send(fmt.Sprintf("NOTICE %s :Denied request for %s.", p.nick, p.channel))
			b.send(fmt.Sprintf("NOTICE %s :Your request for me to monitor %s was denied.", requester, p.channel))
			return
		}
		if b.channels[p.channel] {
			b.send(fmt.Sprintf("NOTICE %s :Already monitoring %s.", p.nick, p.channel))
			return
		}
		b.channels[p.channel] = true
		b.send("JOIN " + p.channel)
		log.Printf("REQUEST for %s (from %s) APPROVED by %s", p.channel, requester, p.nick)
		b.send(fmt.Sprintf("NOTICE %s :Approved -- joined %s.", p.nick, p.channel))
		b.send(fmt.Sprintf("NOTICE %s :Your request for me to monitor %s was approved.", requester, p.channel))

	case "SETTINGS":
		for _, line := range b.settingsLines() {
			b.send(fmt.Sprintf("NOTICE %s :%s", p.nick, line))
		}

	case "SET":
		if err := b.applySetting(p.setKey, p.setValue); err != nil {
			b.send(fmt.Sprintf("NOTICE %s :%v", p.nick, err))
			return
		}
		b.saveSettings()
		log.Printf("SET %s = %q, requested by %s (account %s) -- saved to %s", p.setKey, p.setValue, p.nick, p.account, b.cfg.StateFile)
		b.send(fmt.Sprintf("NOTICE %s :%s set to %s (persisted).", p.nick, p.setKey, p.setValue))

	case "CHANSETTINGS":
		b.send(fmt.Sprintf("NOTICE %s :Effective settings for %s (global values shown where no override exists):", p.nick, p.channel))
		for _, line := range b.channelSettingsLines(p.channel) {
			b.send(fmt.Sprintf("NOTICE %s :%s", p.nick, line))
		}

	case "CHANSET":
		key := strings.ToUpper(p.setKey)
		if b.channelOverrides[p.channel] == nil {
			b.channelOverrides[p.channel] = map[string]string{}
		}
		b.channelOverrides[p.channel][key] = p.setValue
		b.saveSettings()
		log.Printf("CHANSET %s %s = %q, requested by %s (account %s) -- saved to %s", p.channel, key, p.setValue, p.nick, p.account, b.cfg.StateFile)
		b.send(fmt.Sprintf("NOTICE %s :%s for %s set to %s (persisted).", p.nick, key, p.channel, p.setValue))

	case "CHANRESET":
		if strings.EqualFold(p.setKey, "ALL") {
			delete(b.channelOverrides, p.channel)
			log.Printf("CHANRESET %s ALL, requested by %s (account %s)", p.channel, p.nick, p.account)
			b.send(fmt.Sprintf("NOTICE %s :Cleared all overrides for %s -- back to global settings.", p.nick, p.channel))
		} else {
			key := strings.ToUpper(p.setKey)
			delete(b.channelOverrides[p.channel], key)
			if len(b.channelOverrides[p.channel]) == 0 {
				delete(b.channelOverrides, p.channel)
			}
			log.Printf("CHANRESET %s %s, requested by %s (account %s)", p.channel, key, p.nick, p.account)
			b.send(fmt.Sprintf("NOTICE %s :%s for %s reset to the global default.", p.nick, key, p.channel))
		}
		b.saveSettings()
	}
}

// settingsLines is for the human-facing SETTINGS reply only -- grouped
// PERMIT+WINDOW pairs on one line for readability. Deliberately NOT used
// for persistence (see settingsMap for that) -- saveSettings used to
// parse these lines by splitting on the first "=", which silently
// mangled every PERMIT value into "<number> <WINDOW_KEY>=<window>s"
// instead of two separate keys (found live, 2026-08-18, checking the
// actual saved JSON after a SET REPEAT_PERMIT 20 test -- the file
// had "REPEAT_PERMIT": "20 REPEAT_WINDOW=30s" and no REPEAT_WINDOW key
// at all, which would have silently failed to restore either value on
// a real restart).
func (b *Bot) settingsLines() []string {
	c := b.cfg
	return []string{
		fmt.Sprintf("FLOOD_PERMIT=%d FLOOD_WINDOW=%ds", c.FloodPermit, int(c.FloodWindow.Seconds())),
		fmt.Sprintf("MASSJOIN_PERMIT=%d MASSJOIN_WINDOW=%ds", c.MassJoinPermit, int(c.MassJoinWindow.Seconds())),
		fmt.Sprintf("REPEAT_PERMIT=%d REPEAT_WINDOW=%ds", c.RepeatPermit, int(c.RepeatWindow.Seconds())),
		fmt.Sprintf("JOINPART_PERMIT=%d JOINPART_WINDOW=%ds", c.JoinPartPermit, int(c.JoinPartWindow.Seconds())),
		fmt.Sprintf("KLINE_MINUTES=%d", c.KlineDurationMin),
		fmt.Sprintf("KLINE_MESSAGE=%s", c.KlineMessage),
		fmt.Sprintf("MIN_CHANNEL_SIZE=%d", c.MinChannelSize),
		fmt.Sprintf("STAFF_EXEMPT_PATTERN=%s", c.StaffExemptPattern),
	}
}

// settingsMap is persistence's own source of truth -- one clean
// key/value pair per savedSettingsKeys entry, each value formatted
// exactly as applyToConfig expects to parse it back (plain integers for
// *_PERMIT/*_WINDOW/KLINE_MINUTES/MIN_CHANNEL_SIZE -- seconds, not a
// "40s" suffix -- and the raw string for KLINE_MESSAGE/
// STAFF_EXEMPT_PATTERN). Used by saveSettings; NOT used by the
// human-facing SETTINGS reply, which stays on settingsLines above.
func (b *Bot) settingsMap() map[string]string {
	c := b.cfg
	return map[string]string{
		"FLOOD_PERMIT":         strconv.Itoa(c.FloodPermit),
		"FLOOD_WINDOW":         strconv.Itoa(int(c.FloodWindow.Seconds())),
		"MASSJOIN_PERMIT":      strconv.Itoa(c.MassJoinPermit),
		"MASSJOIN_WINDOW":      strconv.Itoa(int(c.MassJoinWindow.Seconds())),
		"REPEAT_PERMIT":        strconv.Itoa(c.RepeatPermit),
		"REPEAT_WINDOW":        strconv.Itoa(int(c.RepeatWindow.Seconds())),
		"JOINPART_PERMIT":      strconv.Itoa(c.JoinPartPermit),
		"JOINPART_WINDOW":      strconv.Itoa(int(c.JoinPartWindow.Seconds())),
		"KLINE_MINUTES":        strconv.Itoa(c.KlineDurationMin),
		"KLINE_MESSAGE":        c.KlineMessage,
		"MIN_CHANNEL_SIZE":     strconv.Itoa(c.MinChannelSize),
		"STAFF_EXEMPT_PATTERN": c.StaffExemptPattern,
	}
}

// effectiveConfig resolves a channel's per-channel threshold overrides
// on top of the global b.cfg -- CHANSET only ever touches the 8
// detection-threshold keys in validChannelSettingKeys below, never
// KLINE_MINUTES/KLINE_MESSAGE/STAFF_EXEMPT_PATTERN, which stay uniform
// network-wide on purpose: how sensitive detection is should vary by
// channel, but what happens once it fires (ban length, message, staff
// exemption) shouldn't. Called on every JOIN/PART/PRIVMSG, not cached
// -- there are at most 8 keys per channel and this only runs on actual
// channel traffic, not a hot path worth optimizing.
func (b *Bot) effectiveConfig(channel string) Config {
	c := b.cfg
	for key, value := range b.channelOverrides[channel] {
		applyToConfig(&c, key, value) // already validated at CHANSET time, error impossible here
	}
	return c
}

// validChannelSettingKeys is CHANSET/CHANRESET's own key list --
// deliberately narrower than validSettingKeys above (SET's global
// list): only the 8 detection thresholds, see effectiveConfig's own
// comment for why KLINE_*/STAFF_EXEMPT_PATTERN aren't here.
var validChannelSettingKeys = map[string]bool{
	"FLOOD_PERMIT": true, "FLOOD_WINDOW": true,
	"MASSJOIN_PERMIT": true, "MASSJOIN_WINDOW": true,
	"REPEAT_PERMIT": true, "REPEAT_WINDOW": true,
	"JOINPART_PERMIT": true, "JOINPART_WINDOW": true,
}

// validateChannelSetting mirrors validateSetting (same pre-WHOIS,
// no-mutation reasoning) but checks against validChannelSettingKeys
// instead of the global validSettingKeys -- every key it allows is an
// integer (seconds or a count), same as validateSetting's non-message
// branch, so the value check is identical.
func validateChannelSetting(key, value string) error {
	upper := strings.ToUpper(key)
	if !validChannelSettingKeys[upper] {
		return fmt.Errorf("unknown per-channel setting %q -- CHANSET only supports thresholds: FLOOD_PERMIT, FLOOD_WINDOW, MASSJOIN_PERMIT, MASSJOIN_WINDOW, REPEAT_PERMIT, REPEAT_WINDOW, JOINPART_PERMIT, JOINPART_WINDOW", key)
	}
	if _, err := strconv.Atoi(value); err != nil {
		return fmt.Errorf("%s needs an integer, got %q", key, value)
	}
	return nil
}

// channelSettingsLines is CHANSETTINGS's reply -- shows the channel's
// EFFECTIVE values (global defaults with any override already applied
// via effectiveConfig), marking which keys are actually overridden for
// this channel specifically vs just inherited from the global SET
// values, matching settingsLines' own PERMIT+WINDOW-per-line layout.
func (b *Bot) channelSettingsLines(channel string) []string {
	ov := b.channelOverrides[channel]
	ec := b.effectiveConfig(channel)
	mark := func(key string) string {
		if _, has := ov[key]; has {
			return " (overridden)"
		}
		return ""
	}
	return []string{
		fmt.Sprintf("FLOOD_PERMIT=%d%s FLOOD_WINDOW=%ds%s", ec.FloodPermit, mark("FLOOD_PERMIT"), int(ec.FloodWindow.Seconds()), mark("FLOOD_WINDOW")),
		fmt.Sprintf("MASSJOIN_PERMIT=%d%s MASSJOIN_WINDOW=%ds%s", ec.MassJoinPermit, mark("MASSJOIN_PERMIT"), int(ec.MassJoinWindow.Seconds()), mark("MASSJOIN_WINDOW")),
		fmt.Sprintf("REPEAT_PERMIT=%d%s REPEAT_WINDOW=%ds%s", ec.RepeatPermit, mark("REPEAT_PERMIT"), int(ec.RepeatWindow.Seconds()), mark("REPEAT_WINDOW")),
		fmt.Sprintf("JOINPART_PERMIT=%d%s JOINPART_WINDOW=%ds%s", ec.JoinPartPermit, mark("JOINPART_PERMIT"), int(ec.JoinPartWindow.Seconds()), mark("JOINPART_WINDOW")),
	}
}

// validSettingKeys is checked by both validateSetting (pre-WHOIS, no
// mutation) and applySetting (post-WHOIS, the real mutation) -- see
// handleSet's own comment for why these are two separate functions and
// not one.
var validSettingKeys = map[string]bool{
	"FLOOD_PERMIT": true, "FLOOD_WINDOW": true,
	"MASSJOIN_PERMIT": true, "MASSJOIN_WINDOW": true,
	"REPEAT_PERMIT": true, "REPEAT_WINDOW": true,
	"JOINPART_PERMIT": true, "JOINPART_WINDOW": true,
	"KLINE_MINUTES": true, "KLINE_MESSAGE": true,
	"MIN_CHANNEL_SIZE": true, "STAFF_EXEMPT_PATTERN": true,
}

// validateSetting checks a key/value pair is well-formed WITHOUT
// mutating b.cfg -- used by handleSet to fail fast on a typo'd key
// before ever sending a WHOIS. KLINE_MESSAGE has no format to check
// beyond existing (any non-empty string is valid); every other key
// needs to parse as an integer.
func validateSetting(key, value string) error {
	upper := strings.ToUpper(key)
	if !validSettingKeys[upper] {
		return fmt.Errorf("unknown setting %q -- see HELP for the list", key)
	}
	if upper == "KLINE_MESSAGE" || upper == "STAFF_EXEMPT_PATTERN" {
		return nil
	}
	if _, err := strconv.Atoi(value); err != nil {
		return fmt.Errorf("%s needs an integer, got %q", key, value)
	}
	return nil
}

// applyToConfig is validateSetting's mutating twin -- a pure function
// over a *Config so it can be reused both for a live SET (applySetting
// below, on the running bot's own b.cfg) and for replaying saved
// settings back onto a fresh Config at startup, before any Bot exists
// yet (see loadSavedSettings). Safe without a lock in the live-SET case
// -- everything in this bot runs on the single connectAndRun/dispatch
// goroutine, no concurrent access.
func applyToConfig(cfg *Config, key, value string) error {
	if err := validateSetting(key, value); err != nil {
		return err
	}
	asInt := func() (int, error) {
		return strconv.Atoi(value)
	}
	switch strings.ToUpper(key) {
	case "FLOOD_PERMIT":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.FloodPermit = n
	case "FLOOD_WINDOW":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.FloodWindow = time.Duration(n) * time.Second
	case "MASSJOIN_PERMIT":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.MassJoinPermit = n
	case "MASSJOIN_WINDOW":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.MassJoinWindow = time.Duration(n) * time.Second
	case "REPEAT_PERMIT":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.RepeatPermit = n
	case "REPEAT_WINDOW":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.RepeatWindow = time.Duration(n) * time.Second
	case "JOINPART_PERMIT":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.JoinPartPermit = n
	case "JOINPART_WINDOW":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.JoinPartWindow = time.Duration(n) * time.Second
	case "KLINE_MINUTES":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.KlineDurationMin = n
	case "KLINE_MESSAGE":
		cfg.KlineMessage = value
	case "MIN_CHANNEL_SIZE":
		n, err := asInt()
		if err != nil {
			return err
		}
		cfg.MinChannelSize = n
	case "STAFF_EXEMPT_PATTERN":
		cfg.StaffExemptPattern = value
	default:
		return fmt.Errorf("unknown setting %q -- see HELP for the list", key)
	}
	return nil
}

func (b *Bot) applySetting(key, value string) error {
	return applyToConfig(&b.cfg, key, value)
}

// savedSettingsKeys is the exact set persisted to/restored from
// StateFile -- everything validSettingKeys covers except KLINE_MESSAGE
// isn't excluded, just listed explicitly here so the persisted file's
// shape doesn't silently drift if validSettingKeys ever gains an
// unrelated key for something not meant to be saved.
var savedSettingsKeys = []string{
	"FLOOD_PERMIT", "FLOOD_WINDOW", "MASSJOIN_PERMIT", "MASSJOIN_WINDOW",
	"REPEAT_PERMIT", "REPEAT_WINDOW", "JOINPART_PERMIT", "JOINPART_WINDOW",
	"KLINE_MINUTES", "KLINE_MESSAGE", "MIN_CHANNEL_SIZE", "STAFF_EXEMPT_PATTERN",
}

// persistedSettings is StateFile's on-disk shape since per-channel
// overrides were added (2026-08-18) -- see loadSavedSettings for the
// migration path from the older flat map[string]string shape that
// predates CHANSET (no wrapper, just the global keys at the top
// level).
type persistedSettings struct {
	Global   map[string]string            `json:"global"`
	Channels map[string]map[string]string `json:"channels,omitempty"`
}

// saveSettings writes every current tunable setting -- global and
// per-channel -- to StateFile as one JSON object -- called after every
// successful admin SET/CHANSET/CHANRESET, so changes persist across a
// restart. Whole-file rewrite each time rather than
// an append-only log -- there are only a dozen-ish keys total, even
// with a handful of channel overrides, simplicity wins over any
// efficiency concern here.
func (b *Bot) saveSettings() {
	ps := persistedSettings{Global: b.settingsMap(), Channels: b.channelOverrides}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		log.Printf("saveSettings: marshal failed: %v", err)
		return
	}
	if err := os.WriteFile(b.cfg.StateFile, data, 0o644); err != nil {
		log.Printf("saveSettings: failed writing %s: %v", b.cfg.StateFile, err)
	}
}

// applyGlobal is loadSavedSettings' shared inner loop -- replays a
// saved global-settings map onto cfg, used by both the new-format and
// old-format branches below.
func applyGlobal(cfg *Config, saved map[string]string) {
	for _, key := range savedSettingsKeys {
		value, ok := saved[key]
		if !ok {
			continue
		}
		if err := applyToConfig(cfg, key, value); err != nil {
			log.Printf("loadSavedSettings: %s=%q from saved settings: %v", key, value, err)
			continue
		}
		log.Printf("loadSavedSettings: restored %s=%s", key, value)
	}
}

// loadSavedSettings replays a previously-saved StateFile onto cfg,
// called once at startup (main(), before connectAndRun) so persisted
// SETs survive a restart -- overrides the env-var defaults loadConfig()
// already put in cfg. Missing file is normal (never SET anything yet)
// and not logged as an error; a per-key apply failure (e.g. the file
// was hand-edited badly) is logged but doesn't stop startup -- that
// key just keeps its env-var default. Returns the per-channel override
// map for main() to hand to the freshly-constructed Bot (this runs
// before any Bot exists yet, same reasoning as applyToConfig taking a
// bare *Config instead of a *Bot).
//
// Tries the new {"global":..., "channels":...} shape first
// (persistedSettings, added 2026-08-18 alongside CHANSET); if neither
// field is present, the file predates per-channel overrides -- it's
// the OLD flat {"FLOOD_PERMIT":"30",...} shape with no wrapper, which
// json.Unmarshal into persistedSettings silently leaves both fields
// nil for (unmatched top-level keys are ignored, not an error) rather
// than actually failing, so that's the real signal to fall back on,
// not an unmarshal error. The next saveSettings call migrates the file
// to the new shape automatically.
func loadSavedSettings(cfg *Config) map[string]map[string]string {
	data, err := os.ReadFile(cfg.StateFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadSavedSettings: failed reading %s: %v", cfg.StateFile, err)
		}
		return map[string]map[string]string{}
	}

	var ps persistedSettings
	if err := json.Unmarshal(data, &ps); err == nil && (ps.Global != nil || ps.Channels != nil) {
		applyGlobal(cfg, ps.Global)
		if ps.Channels == nil {
			ps.Channels = map[string]map[string]string{}
		}
		return ps.Channels
	}

	var flat map[string]string
	if err := json.Unmarshal(data, &flat); err != nil {
		log.Printf("loadSavedSettings: failed parsing %s: %v", cfg.StateFile, err)
		return map[string]map[string]string{}
	}
	applyGlobal(cfg, flat)
	return map[string]map[string]string{}
}

// handleSet is SET's entry point -- validates the key/value up front via
// validateSetting (fails fast on a typo without even doing a WHOIS
// round-trip), but deliberately does NOT call the mutating applySetting
// here -- that only ever runs after the WHOIS gate confirms an admin,
// in finishPendingCmd's own "SET" case. Applying it here too would let
// anyone change live thresholds just by typing SET, gate or no gate.
// handleKlineCmd: KLINE [<#channel> ON [minutes] | OFF | STATUS].
// Validated first, acted on only after the WHOIS confirms the account.
func (b *Bot) handleKlineCmd(nick string, args []string) {
	if len(args) == 0 {
		args = []string{"LIST"}
	}
	channel, setValue := "", ""
	if strings.ToUpper(args[0]) != "LIST" {
		if len(args) < 2 || !channelNameRe.MatchString(args[0]) {
			b.send(fmt.Sprintf("NOTICE %s :Syntax: KLINE <#channel> ON [minutes] | OFF | STATUS   (or just KLINE to list)", nick))
			return
		}
		channel = args[0]
		setValue = strings.ToUpper(args[1])
		if setValue != "ON" && setValue != "OFF" && setValue != "STATUS" {
			b.send(fmt.Sprintf("NOTICE %s :Syntax: KLINE <#channel> ON [minutes] | OFF | STATUS", nick))
			return
		}
		if setValue == "ON" && len(args) > 2 {
			setValue = "ON " + args[2]
		}
	}
	if b.pendingCmd != nil && time.Since(b.pendingCmd.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pendingCmd = &pendingChanCmd{nick: nick, kind: "KLINE", channel: channel, setValue: setValue, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

func (b *Bot) finishKlineCmd(p *pendingChanCmd) {
	if !b.cfg.canKline(p.account) {
		log.Printf("KLINE denied: %s (account seen: %q)", p.nick, p.account)
		b.send(fmt.Sprintf("NOTICE %s :Do I know you?", p.nick))
		return
	}
	now := time.Now()
	reply := func(f string, a ...interface{}) { b.send(fmt.Sprintf("NOTICE %s :%s", p.nick, fmt.Sprintf(f, a...))) }
	if p.channel == "" { // list
		n := 0
		for ch, until := range b.klineArmed {
			if now.Before(until) {
				reply("%s armed for another %s", ch, until.Sub(now).Round(time.Minute))
				n++
			}
		}
		if n == 0 {
			reply("KLINE is not armed on any channel.")
		}
		return
	}
	key := strings.ToLower(p.channel)
	fields := strings.Fields(p.setValue)
	switch fields[0] {
	case "STATUS":
		if until, ok := b.klineArmed[key]; ok && now.Before(until) {
			reply("KLINE ARMED on %s for another %s.", p.channel, until.Sub(now).Round(time.Minute))
		} else {
			reply("KLINE not armed on %s (detections only alert).", p.channel)
		}
	case "OFF":
		delete(b.klineArmed, key)
		log.Printf("KLINE OFF %s by %s (account %s)", p.channel, p.nick, p.account)
		reply("KLINE disarmed on %s.", p.channel)
		b.alert("arm:"+key, fmt.Sprintf("KLINE disarmed on %s by %s", p.channel, p.nick))
	case "ON":
		mins := b.cfg.KlineArmMinutes
		if len(fields) > 1 {
			m, err := strconv.Atoi(fields[1])
			if err != nil || m < 1 || m > b.cfg.KlineArmMinutes {
				reply("Minutes must be 1-%d.", b.cfg.KlineArmMinutes)
				return
			}
			mins = m
		}
		if !b.channels[p.channel] {
			b.channels[p.channel] = true
			b.send("JOIN " + p.channel)
			log.Printf("JOIN %s via KLINE ON by %s (account %s)", p.channel, p.nick, p.account)
		}
		b.klineArmed[key] = now.Add(time.Duration(mins) * time.Minute)
		log.Printf("KLINE ON %s for %d min by %s (account %s)", p.channel, mins, p.nick, p.account)
		reply("KLINE ARMED on %s for %d min. Off with: KLINE %s OFF. Paused automatically during a probable netsplit.", p.channel, mins, p.channel)
		b.alert("arm:"+key, fmt.Sprintf("KLINE armed on %s for %d min by %s", p.channel, mins, p.nick))
	}
}

func (b *Bot) handleSet(nick string, args []string) {
	if len(args) < 2 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: SET <key> <value> -- see HELP for the key list.", nick))
		return
	}
	key := args[0]
	value := strings.Join(args[1:], " ")
	if err := validateSetting(key, value); err != nil {
		b.send(fmt.Sprintf("NOTICE %s :%v", nick, err))
		return
	}
	if b.pendingCmd != nil && time.Since(b.pendingCmd.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pendingCmd = &pendingChanCmd{nick: nick, kind: "SET", setKey: key, setValue: value, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// handleChanSet is CHANSET's entry point -- same shape and same
// deliberate validate-before-WHOIS/mutate-only-after-WHOIS split as
// handleSet above, just with a channel argument and the narrower
// validChannelSettingKeys instead of the global list.
func (b *Bot) handleChanSet(nick string, args []string) {
	if len(args) < 3 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: CHANSET <#channel> <key> <value>", nick))
		return
	}
	channel := args[0]
	if !channelNameRe.MatchString(channel) {
		b.send(fmt.Sprintf("NOTICE %s :Invalid channel name.", nick))
		return
	}
	key := args[1]
	value := strings.Join(args[2:], " ")
	if err := validateChannelSetting(key, value); err != nil {
		b.send(fmt.Sprintf("NOTICE %s :%v", nick, err))
		return
	}
	if b.pendingCmd != nil && time.Since(b.pendingCmd.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pendingCmd = &pendingChanCmd{nick: nick, kind: "CHANSET", channel: channel, setKey: key, setValue: value, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// handleChanReset is CHANRESET's entry point -- clears one (or, with
// "ALL", every) per-channel override, falling back to whatever the
// global SET value is. "ALL" is accepted case-insensitively as a
// convenience so clearing a channel doesn't need one CHANRESET per key.
func (b *Bot) handleChanReset(nick string, args []string) {
	if len(args) != 2 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: CHANRESET <#channel> <key-or-ALL>", nick))
		return
	}
	channel := args[0]
	if !channelNameRe.MatchString(channel) {
		b.send(fmt.Sprintf("NOTICE %s :Invalid channel name.", nick))
		return
	}
	key := strings.ToUpper(args[1])
	if key != "ALL" && !validChannelSettingKeys[key] {
		b.send(fmt.Sprintf("NOTICE %s :unknown per-channel setting %q", nick, args[1]))
		return
	}
	if b.pendingCmd != nil && time.Since(b.pendingCmd.createdAt) < 30*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already processing a request, try again shortly.", nick))
		return
	}
	b.pendingCmd = &pendingChanCmd{nick: nick, kind: "CHANRESET", channel: channel, setKey: key, createdAt: time.Now()}
	b.send("WHOIS " + nick)
}

// handleRequest is REQUEST's entry point -- deliberately open to anyone
// (no WHOIS gate, unlike JOIN/PART/APPROVE/DENY above): any channel's
// own people can ask, but an admin still has to
// APPROVE before this bot actually joins and starts issuing KLINEs
// there. First checks the channel's member count against
// MinChannelSize via NAMES -- no point bothering the admin with tiny/
// irrelevant channels.
func (b *Bot) handleRequest(nick string, args []string) {
	if len(args) != 1 {
		b.send(fmt.Sprintf("NOTICE %s :Syntax: REQUEST <#channel>", nick))
		return
	}
	channel := args[0]
	if !channelNameRe.MatchString(channel) {
		b.send(fmt.Sprintf("NOTICE %s :Invalid channel name.", nick))
		return
	}
	if b.channels[channel] {
		b.send(fmt.Sprintf("NOTICE %s :Already monitoring %s.", nick, channel))
		return
	}
	if _, already := b.pendingRequests[channel]; already {
		b.send(fmt.Sprintf("NOTICE %s :%s already has a pending request, waiting on admin approval.", nick, channel))
		return
	}
	if b.pendingReq != nil && time.Since(b.pendingReq.createdAt) < 15*time.Second {
		b.send(fmt.Sprintf("NOTICE %s :Already checking a request, try again shortly.", nick))
		return
	}
	b.pendingReq = &pendingSizeCheck{nick: nick, channel: channel, createdAt: time.Now()}
	b.send("NAMES " + channel)
}

func (b *Bot) finishPendingRequest() {
	p := b.pendingReq
	b.pendingReq = nil

	if p.count < b.cfg.MinChannelSize {
		b.send(fmt.Sprintf("NOTICE %s :%s has too few members (%d, need at least %d) -- not queuing a request.",
			p.nick, p.channel, p.count, b.cfg.MinChannelSize))
		return
	}
	b.pendingRequests[p.channel] = p.nick
	log.Printf("REQUEST for %s from %s (%d members) -- queued for admin approval", p.channel, p.nick, p.count)
	b.send(fmt.Sprintf("NOTICE %s :Request queued (%d members) -- an admin needs to APPROVE it.", p.nick, p.count))
	// Visible in the main channel rather than a PM to a specific nick --
	// this bot doesn't track which nick the admin is using right now
	// (see this file's own top comment), but the admin is reliably
	// around #chatnet.
	b.send(fmt.Sprintf("PRIVMSG %s :[Sentry] %s requested monitoring for %s (%d members) -- an admin can /msg %s APPROVE %s or DENY %s",
		b.cfg.MainChannel, p.nick, p.channel, p.count, b.cfg.Nick, p.channel, p.channel))
}

// ---- one-time access notice for KLINE accounts ----------------------

const klineAccessNotice = "Hi, I'm Sentry, ChatNet's anti-abuse bot. You have been given access to my KLINE command. " +
	"If a real attack hits a channel: /msg Sentry KLINE #channel ON arms automatic network bans there " +
	"(default 1 day, then it disarms itself; KLINE #channel OFF stops it). " +
	"I never ban anyone on my own unless one of you arms it, and I pause during a netsplit. Send me HELP for everything else."

func (b *Bot) notifiedPath() string {
	return filepath.Join(filepath.Dir(b.cfg.StateFile), "kline-notified.json")
}

func (b *Bot) loadNotified() {
	data, err := os.ReadFile(b.notifiedPath())
	if err != nil {
		return
	}
	var list []string
	if json.Unmarshal(data, &list) == nil {
		for _, a := range list {
			b.notifyDone[strings.ToLower(a)] = true
		}
	}
}

func (b *Bot) saveNotified() {
	list := make([]string, 0, len(b.notifyDone))
	for a := range b.notifyDone {
		list = append(list, a)
	}
	sort.Strings(list)
	data, _ := json.Marshal(list)
	tmp := b.notifiedPath() + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		os.Rename(tmp, b.notifiedPath())
	}
}

// tickNotify sends the access notice to every KLINE account not yet told,
// treating the account name as the nick. No 401 within 15 s counts as
// delivered; otherwise it is retried every 10 minutes.
func (b *Bot) tickNotify(now time.Time) {
	if b.notifyReady.IsZero() || now.Before(b.notifyReady) {
		return
	}
	changed := false
	for n, t := range b.notifySent {
		if now.Sub(t) > 15*time.Second {
			b.notifyDone[n] = true
			delete(b.notifySent, n)
			changed = true
			log.Printf("KLINE access notice delivered to %s", n)
		}
	}
	if changed {
		b.saveNotified()
	}
	if now.Sub(b.lastNotify) < 10*time.Minute {
		return
	}
	b.lastNotify = now
	for _, a := range b.cfg.KlineAccounts {
		k := strings.ToLower(a)
		if k == "" || strings.ContainsAny(a, " ,:#") || b.notifyDone[k] {
			continue
		}
		if _, pending := b.notifySent[k]; pending {
			continue
		}
		b.send(fmt.Sprintf("PRIVMSG %s :%s", a, klineAccessNotice))
		b.notifySent[k] = now
	}
}
