package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// Idle ticks fire on a silent connection, and a line split across an idle
// timeout arrives whole.
func TestReadLinesIdleTickAndSplitLine(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	var mu sync.Mutex
	var lines []string
	idle := 0
	done := make(chan error, 1)
	go func() {
		done <- readLines(c1, 30*time.Millisecond,
			func(l string) { mu.Lock(); lines = append(lines, l); mu.Unlock() },
			func() { mu.Lock(); idle++; mu.Unlock() })
	}()
	time.Sleep(120 * time.Millisecond) // silent: must tick
	c2.Write([]byte("PING :a"))
	time.Sleep(100 * time.Millisecond) // timeout in the middle of a line
	c2.Write([]byte("bc\r\n:x PRIVMSG #c :hi\r\n"))
	time.Sleep(60 * time.Millisecond)
	c2.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if idle < 2 {
		t.Fatalf("idle ticks=%d, want >=2", idle)
	}
	if len(lines) != 2 || lines[0] != "PING :abc" || lines[1] != ":x PRIVMSG #c :hi" {
		t.Fatalf("lines=%q", lines)
	}
}
