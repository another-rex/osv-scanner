// Package testlogger provides a slog handler which can handle t.Parallel() tests while being a global logging handler,
// redirecting it to the correct underlying logger for each test thread.
package testlogger

import (
	"bufio"
	"bytes"
	"context"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
)

// Handler can be set as the global logging handler before the test starts, and individual test cases can add their
// own instance/implementation of the cmdlogger.CmdLogger interface.
type Handler struct {
	loggerMap sync.Map // map[string]cmdlogger.CmdLogger
}

func (tl *Handler) getLogger() cmdlogger.CmdLogger {
	key := getCallerInstance()
	val, ok := tl.loggerMap.Load(key)
	if !ok {
		panic("logger not found: " + key)
	}

	return val.(cmdlogger.CmdLogger)
}

// AddInstance adds a "global" logger to this specific test run.
func (tl *Handler) AddInstance(logger cmdlogger.CmdLogger) {
	key := getCallerInstance()
	prev, _ := tl.loggerMap.Swap(key, logger)
	if prev != nil {
		// This is used as a safety check for incorrect usage of the Handler, and should never happen
		// during actual tests if Delete() is correctly called at the end of a test.
		panic("same logger being added twice")
	}
}

// Delete removes the logger created by AddInstance()
// This **must** be called before a test ends, as the same memory address may be reused.
func (tl *Handler) Delete() {
	tl.loggerMap.Delete(getCallerInstance())
}

// SendEverythingToStderr tells the logger to send all logs to stderr regardless
// of their level.
//
// This is useful if we're expecting to output structured data to stdout such
// as JSON, which cannot be mixed with other output.
func (tl *Handler) SendEverythingToStderr() {
	tl.getLogger().SendEverythingToStderr()
}

func (tl *Handler) SetLevel(level slog.Leveler) {
	tl.getLogger().SetLevel(level)
}

func (tl *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return tl.getLogger().Enabled(ctx, level)
}

func (tl *Handler) Handle(ctx context.Context, record slog.Record) error {
	return tl.getLogger().Handle(ctx, record)
}

// HasErrored returns true if there have been any calls to Handle with
// a level of [slog.LevelError]
func (tl *Handler) HasErrored() bool {
	return tl.getLogger().HasErrored()
}

func (tl *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return tl.getLogger().WithAttrs(attrs)
}

func (tl *Handler) WithGroup(g string) slog.Handler {
	return tl.getLogger().WithGroup(g)
}

var _ cmdlogger.CmdLogger = &Handler{}

func New() *Handler {
	return &Handler{
		loggerMap: sync.Map{},
	}
}

// getCallerInstance finds in the call stack the memory address of the initial test runner call.
// It will look something like this:
//
// `testing.tRunner(0x12345678, 0x98765432)`
//
// This is safe to be used as a key, as the first pointer address must be unique
// while this test is running, and will only be reused after the test exists and that address is garbage collected.
//
// This uses debug.Stack(), which will create a buffer big enough to fit the entire stack trace.
// If there is deep recursion, this will have a significant performance cost.
func getCallerInstance() string {
	stack := debug.Stack()
	sc := bufio.NewScanner(bytes.NewReader(stack))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "testing.tRunner(") {
			return sc.Text()
		}
	}

	panic("no caller found in stack, recursed too deep?")
}
