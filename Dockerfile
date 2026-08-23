# Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
#
# Sentry -- ChatNet's own anti-abuse bot (see main.go's own header
# comment for why this exists instead of the removed Ozone/Sigyn).
# Same hand-rolled IRC client pattern as cncheck-bot/znc-bot -- no IRC
# library exists anywhere in this project.

FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY main.go irc.go ./
RUN go build -o /opt/sentry/sentry .

FROM alpine:latest

RUN adduser -D -h /home/sentry sentry

# Persisted SET settings, see main.go's loadSavedSettings/saveSettings. Created
# and chowned here explicitly -- a named volume mounted on a path that
# doesn't already exist in the image gets auto-created root-owned on
# first mount, which would leave this non-root user unable to write to
# it (same class of bug already hit and documented elsewhere in this
# project for other bots' data dirs).
RUN mkdir -p /data && chown sentry:sentry /data

COPY --from=build /opt/sentry/sentry /opt/sentry/sentry

USER sentry
WORKDIR /home/sentry
ENTRYPOINT ["/opt/sentry/sentry"]
