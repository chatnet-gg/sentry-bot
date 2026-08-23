// Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.

package main

import (
	"strings"
)

// Line is a parsed IRC protocol line: ":prefix COMMAND param1 param2 :trailing"
// Same minimal parser as cncheck-bot/znc-bot's own irc.go (copied, not
// imported -- these are separate small Go binaries in this project, not
// a shared package).
type Line struct {
	Prefix   string
	Nick     string
	Ident    string
	Host     string
	Command  string
	Params   []string
	Trailing string
	Raw      string
}

func parseLine(raw string) Line {
	l := Line{Raw: raw}
	s := raw

	if strings.HasPrefix(s, ":") {
		sp := strings.IndexByte(s, ' ')
		if sp == -1 {
			l.Prefix = s[1:]
			return l
		}
		l.Prefix = s[1:sp]
		s = s[sp+1:]
	}

	if bang := strings.IndexByte(l.Prefix, '!'); bang != -1 {
		l.Nick = l.Prefix[:bang]
		rest := l.Prefix[bang+1:]
		if at := strings.IndexByte(rest, '@'); at != -1 {
			l.Ident = rest[:at]
			l.Host = rest[at+1:]
		}
	} else if l.Prefix != "" && !strings.Contains(l.Prefix, ".") {
		l.Nick = l.Prefix
	}

	if idx := strings.Index(s, " :"); idx != -1 {
		l.Trailing = s[idx+2:]
		s = s[:idx]
	} else if strings.HasPrefix(s, ":") {
		l.Trailing = s[1:]
		s = ""
	}

	fields := strings.Fields(s)
	if len(fields) > 0 {
		l.Command = fields[0]
		l.Params = fields[1:]
	}
	return l
}

func (l Line) text() string {
	if l.Trailing != "" {
		return l.Trailing
	}
	if len(l.Params) > 1 {
		return l.Params[len(l.Params)-1]
	}
	return ""
}

func (l Line) target() string {
	if len(l.Params) > 0 {
		return l.Params[0]
	}
	return ""
}
