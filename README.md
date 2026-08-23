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

## License

MIT, see [LICENSE](LICENSE).
