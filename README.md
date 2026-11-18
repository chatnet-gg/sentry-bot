# sentry-bot

Anti-abuse IRC bot. Watches its monitored channels for message flood,
repeated messages, mass-join (clone-army) bursts, and join/part
flooding, and issues a temporary KLINE against the real offending host
(resolved via WHOIS, not the cloak) when one fires. Admins manage
monitored channels and thresholds live over PM -- see `HELP`.

## Requirements

- Go 1.22+ (or just Docker)
- An IRC operator account for the bot with KLINE/UNKLINE and
  auspex:hostname privileges, and a NickServ account for it to identify
  with

## Run

```sh
docker build -t sentry-bot .
docker run -d --name sentry-bot -v sentry-data:/data \
  -e SENTRY_NICKSERV_PASSWORD=... \
  -e SENTRY_OPER_PASSWORD=... \
  sentry-bot
```

Optional env vars (with their defaults): `IRC_SERVER`
(irc.chatnet.gg), `IRC_PORT` (6697), `SENTRY_NICK` (Sentry),
`SENTRY_MAIN_CHANNEL` (#chatnet), `SENTRY_ADMIN_ACCOUNTS`, detection
thresholds (`SENTRY_FLOOD_PERMIT`, `SENTRY_MASSJOIN_PERMIT`, etc, all
tunable live via `SET`/`CHANSET`) -- see `main.go`'s `loadConfig` for
the full list.

## Off by default, and protected against false positives

A relink or a hub restart looks exactly like a join attack from a client's
seat: everyone leaves and comes back within seconds. Sentry therefore does
**not** join any channel at start-up (set `SENTRY_AUTOJOIN=1` to restore the
old behaviour for `SENTRY_MAIN_CHANNEL`); an admin turns monitoring on per
channel with `JOIN <#channel>`.

While it watches, these guards keep the detections away from real users
(see `guard.go` for the reasoning):

- **Netsplits:** nicks that quit with a split-style reason are remembered, and
  their rejoin is not counted; the netjoin also opens a short window
  (`SENTRY_NETJOIN_WINDOW_SEC`, 90 s) in which unknown hosts are not counted.
  With `flatten_links = yes` the server writes the fixed text `*.net *.split`
  instead of the server names, and that is recognised too. Independently of
  the text, 8 or more known members quitting within 10 seconds (a hub reset,
  say) is treated as a probable split: nothing is actioned for 10 minutes.
- **Presence:** nicks already in the channel (tracked from NAMES, JOIN, PART,
  QUIT, KICK and NICK) and hosts seen for a while
  (`SENTRY_KNOWN_AFTER_SEC`, kept in `SENTRY_KNOWN_FILE` for
  `SENTRY_KNOWN_TTL_DAYS`) are not counted either. Nothing is actioned during
  the warm-up after a (re)connect (`SENTRY_WARMUP_SEC`, 300 s).
- **Never your own infrastructure:** `chatnet/` cloaks, the domain suffixes in
  `SENTRY_INFRA_SUFFIXES`, private addresses and the server addresses listed in
  `SENTRY_INFRA_IPS` (empty by default: set it to your own servers) are never
  K-lined. `SENTRY_STAFF_EXEMPT_PATTERN` takes a comma-separated list of exempt
  cloak prefixes.
- **Circuit breaker:** at most `SENTRY_MAX_KLINES_10MIN` K-lines (10) in ten
  minutes; after that Sentry pauses for `SENTRY_BREAKER_PAUSE_MIN` minutes.

`go test ./...` covers each of these, including a 200-user netsplit rejoin.

## KLINE only when a person arms it

Detections are never allowed to ban by themselves. By default a flood,
repeat or mass-join detection only logs a line and, if `SENTRY_ALERT_TARGET`
is set (a nick or a channel), sends a short NOTICE saying that nobody was
banned and how to arm the channel.

A person arms KLINE for one channel by private message (WHOIS-verified, like
every command):

- `KLINE <#channel> ON [minutes]` -- arm it (joins the channel if needed).
  The default and maximum duration is `SENTRY_KLINE_ARM_MINUTES` (1 day).
- `KLINE <#channel> OFF` -- disarm it. `KLINE <#channel> STATUS` shows the
  state, and `KLINE` alone lists the armed channels.

Admins can always arm; `SENTRY_KLINE_ACCOUNTS` (comma-separated accounts) adds
people who may arm but are not admins. The arm is **never persisted**, so a
restart disarms everything, it expires by itself, it is checked again when a
queued K-line is about to be sent, and it is suspended during a probable
netsplit or the warm-up after a reconnect.

## License

MIT, see [LICENSE](LICENSE).
