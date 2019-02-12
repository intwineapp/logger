/*
Copyright 2018 Intwine Labs, Inc. All Rights Reserved.
Copyright 2016 Google Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package logger offers simple cross platform logging for Windows and Linux.
// Available logging endpoints are event log (Windows), syslog (Linux), and
// an io.Writer.
package logger

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/Microsoft/ApplicationInsights-Go/appinsights/contracts"

	"github.com/Microsoft/ApplicationInsights-Go/appinsights"
)

type severity int

// Severity levels.
const (
	sInfo severity = iota
	sWarning
	sError
	sFatal
)

// Severity tags.
const (
	tagInfo    = "INFO : "
	tagWarning = "WARN : "
	tagError   = "ERROR: "
	tagFatal   = "FATAL: "
)

const (
	flags    = log.Ldate | log.Lmicroseconds | log.Lshortfile
	initText = "ERROR: Logging before logger.Init.\n"
)

var (
	logLock       sync.Mutex
	defaultLogger *Logger
)

// initialize resets defaultLogger.  Which allows tests to reset environment.
func initialize() {
	defaultLogger = &Logger{
		infoLog:    log.New(os.Stderr, initText+tagInfo, flags),
		warningLog: log.New(os.Stderr, initText+tagWarning, flags),
		errorLog:   log.New(os.Stderr, initText+tagError, flags),
		fatalLog:   log.New(os.Stderr, initText+tagFatal, flags),
	}
}

func init() {
	initialize()
}

// Init sets up logging and should be called before log functions, usually in
// the caller's main(). Default log functions can be called before Init(), but log
// output will only go to stderr (along with a warning).
// The first call to Init populates the default logger and returns the
// generated logger, subsequent calls to Init will only return the generated
// logger.
// If the logFile passed in also satisfies io.Closer, logFile.Close will be called
// when closing the logger.
func Init(name string, verbose, systemLog bool, logFile io.Writer) *Logger {
	var il, wl, el io.Writer
	if systemLog {
		var err error
		il, wl, el, err = setup(name)
		if err != nil {
			log.Fatal(err)
		}
	}

	iLogs := []io.Writer{logFile}
	wLogs := []io.Writer{logFile}
	eLogs := []io.Writer{logFile}
	if il != nil {
		iLogs = append(iLogs, il)
	}
	if wl != nil {
		wLogs = append(wLogs, wl)
	}
	if el != nil {
		eLogs = append(eLogs, el)
	}
	// Windows services don't have stdout/stderr. Writes will fail, so try them last.
	eLogs = append(eLogs, os.Stderr)
	if verbose {
		iLogs = append(iLogs, os.Stdout)
		wLogs = append(wLogs, os.Stdout)
	}

	l := Logger{
		infoLog:    log.New(io.MultiWriter(iLogs...), tagInfo, flags),
		warningLog: log.New(io.MultiWriter(wLogs...), tagWarning, flags),
		errorLog:   log.New(io.MultiWriter(eLogs...), tagError, flags),
		fatalLog:   log.New(io.MultiWriter(eLogs...), tagFatal, flags),
	}
	for _, w := range []io.Writer{logFile, il, wl, el} {
		if c, ok := w.(io.Closer); ok && c != nil {
			l.closers = append(l.closers, c)
		}
	}
	l.initialized = true

	logLock.Lock()
	defer logLock.Unlock()
	if !defaultLogger.initialized {
		defaultLogger = &l
	}

	return &l
}

// New return a default Logger
func New() *Logger {
	return Init("", true, false, ioutil.Discard)
}

// A Logger represents an active logging object. Multiple loggers can be used
// simultaneously even if they are using the same same writers.
type Logger struct {
	infoLog     *log.Logger
	warningLog  *log.Logger
	errorLog    *log.Logger
	fatalLog    *log.Logger
	closers     []io.Closer
	client      appinsights.TelemetryClient
	name        string
	remoteLog   bool
	initialized bool
}

func (l *Logger) output(s severity, depth int, txt string) {
	logLock.Lock()
	defer logLock.Unlock()
	switch s {
	case sInfo:
		l.infoLog.Output(3+depth, txt)
	case sWarning:
		l.warningLog.Output(3+depth, txt)
	case sError:
		l.errorLog.Output(3+depth, txt)
	case sFatal:
		l.fatalLog.Output(3+depth, txt)
	default:
		panic(fmt.Sprintln("unrecognized severity:", s))
	}
}

type Config struct {
	Key              string
	MaxBatchInterval time.Duration
	MaxBatchSize     int
}

func (l *Logger) Config(conf Config) {
	telemetryClientConfig := appinsights.NewTelemetryConfiguration(conf.Key)
	if conf.MaxBatchInterval != 0 {
		telemetryClientConfig.MaxBatchInterval = conf.MaxBatchInterval
	} else {
		telemetryClientConfig.MaxBatchInterval = 1 * time.Second
	}
	if conf.MaxBatchSize != 0 {
		telemetryClientConfig.MaxBatchSize = conf.MaxBatchSize
	} else {
		telemetryClientConfig.MaxBatchSize = 1024
	}
	telemetryClient := appinsights.NewTelemetryClientFromConfig(telemetryClientConfig)
	l.client = telemetryClient
	l.remoteLog = true
}

// Flush flushes buffered logs
func (l *Logger) Flush() {
	if l.remoteLog {
		l.client.Channel().Flush()
	}
}

// Close closes all the underlying log writers, which will flush any cached logs.
// Any errors from closing the underlying log writers will be printed to stderr.
// Once Close is called, all future calls to the logger will panic.
func (l *Logger) Close() {
	logLock.Lock()
	defer logLock.Unlock()
	for _, c := range l.closers {
		if err := c.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close log %v: %v\n", c, err)
		}
	}

	if l.remoteLog {
		l.Flush()
		<-l.client.Channel().Close(10 * time.Second)
	}
}

// Info logs with the Info severity.
// Arguments are handled in the manner of fmt.Print.
func (l *Logger) Info(v ...interface{}) {
	l.output(sInfo, 0, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Information, v)
	}
}

// InfoDepth acts as Info but uses depth to determine which call frame to log.
// InfoDepth(0, "msg") is the same as Info("msg").
func (l *Logger) InfoDepth(depth int, v ...interface{}) {
	l.output(sInfo, depth, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(depth, appinsights.Information, v)
	}
}

// Infoln logs with the Info severity.
// Arguments are handled in the manner of fmt.Println.
func (l *Logger) Infoln(v ...interface{}) {
	l.output(sInfo, 0, fmt.Sprintln(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Information, v)
	}
}

// Infof logs with the Info severity.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Infof(format string, v ...interface{}) {
	l.output(sInfo, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Information, format, v)
	}
}

// InfoWith logs with the Info severity.
// Arguments are handled as structured key val pairs.
func (l *Logger) InfoWith(format string, v ...interface{}) {
	l.output(sInfo, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitStructured(0, appinsights.Information, format, v)
	}
}

// Warning logs with the Warning severity.
// Arguments are handled in the manner of fmt.Print.
func (l *Logger) Warning(v ...interface{}) {
	l.output(sWarning, 0, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Warning, v)
	}
}

// WarningDepth acts as Warning but uses depth to determine which call frame to log.
// WarningDepth(0, "msg") is the same as Warning("msg").
func (l *Logger) WarningDepth(depth int, v ...interface{}) {
	l.output(sWarning, depth, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(depth, appinsights.Warning, v)
	}
}

// Warningln logs with the Warning severity.
// Arguments are handled in the manner of fmt.Println.
func (l *Logger) Warningln(v ...interface{}) {
	l.output(sWarning, 0, fmt.Sprintln(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Warning, v)
	}
}

// Warningf logs with the Warning severity.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Warningf(format string, v ...interface{}) {
	l.output(sWarning, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Warning, format, v)
	}
}

// WarningWith logs with the Warning severity.
// Arguments are handled as structured key val pairs.
func (l *Logger) WarningWith(format string, v ...interface{}) {
	l.output(sWarning, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitStructured(0, appinsights.Warning, format, v)
	}
}

// Error logs with the ERROR severity.
// Arguments are handled in the manner of fmt.Print.
func (l *Logger) Error(v ...interface{}) {
	l.output(sError, 0, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, v)
	}
}

// ErrorDepth acts as Error but uses depth to determine which call frame to log.
// ErrorDepth(0, "msg") is the same as Error("msg").
func (l *Logger) ErrorDepth(depth int, v ...interface{}) {
	l.output(sError, depth, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(depth, appinsights.Error, v)
	}
}

// Errorln logs with the ERROR severity.
// Arguments are handled in the manner of fmt.Println.
func (l *Logger) Errorln(v ...interface{}) {
	l.output(sError, 0, fmt.Sprintln(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, v)
	}
}

// Errorf logs with the Error severity.
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Errorf(format string, v ...interface{}) {
	l.output(sError, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, format, v)
	}
}

// ErrorWith logs with the Error severity.
// Arguments are handled as structured key val pairs.
func (l *Logger) ErrorWith(format string, v ...interface{}) {
	l.output(sError, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, format, v)
	}
}

// Fatal logs with the Fatal severity, and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Print.
func (l *Logger) Fatal(v ...interface{}) {
	l.output(sFatal, 0, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, v)
	}
	l.Close()
	os.Exit(1)
}

// FatalDepth acts as Fatal but uses depth to determine which call frame to log.
// FatalDepth(0, "msg") is the same as Fatal("msg").
func (l *Logger) FatalDepth(depth int, v ...interface{}) {
	l.output(sFatal, depth, fmt.Sprint(v...))
	if l.remoteLog {
		l.emitUnstructured(depth, appinsights.Error, v)
	}
	l.Close()
	os.Exit(1)
}

// Fatalln logs with the Fatal severity, and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Println.
func (l *Logger) Fatalln(v ...interface{}) {
	l.output(sFatal, 0, fmt.Sprintln(v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, v)
	}
	l.Close()
	os.Exit(1)
}

// Fatalf logs with the Fatal severity, and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Printf.
func (l *Logger) Fatalf(format string, v ...interface{}) {
	l.output(sFatal, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, format, v)
	}
	l.Close()
	os.Exit(1)
}

// FatalWith logs with the Fatal severity, and ends with os.Exit(1).
// Arguments are handled as structured key val pairs.
func (l *Logger) FatalWith(format string, v ...interface{}) {
	l.output(sFatal, 0, fmt.Sprintf(format, v...))
	if l.remoteLog {
		l.emitUnstructured(0, appinsights.Error, format, v)
	}
	l.Close()
	os.Exit(1)
}

// Info uses the default logger and logs with the Info severity.
// Arguments are handled in the manner of fmt.Print.
func Info(v ...interface{}) {
	defaultLogger.output(sInfo, 0, fmt.Sprint(v...))
}

// InfoDepth acts as Info but uses depth to determine which call frame to log.
// InfoDepth(0, "msg") is the same as Info("msg").
func InfoDepth(depth int, v ...interface{}) {
	defaultLogger.output(sInfo, depth, fmt.Sprint(v...))
}

// Infoln uses the default logger and logs with the Info severity.
// Arguments are handled in the manner of fmt.Println.
func Infoln(v ...interface{}) {
	defaultLogger.output(sInfo, 0, fmt.Sprintln(v...))
}

// Infof uses the default logger and logs with the Info severity.
// Arguments are handled in the manner of fmt.Printf.
func Infof(format string, v ...interface{}) {
	defaultLogger.output(sInfo, 0, fmt.Sprintf(format, v...))
}

// Warning uses the default logger and logs with the Warning severity.
// Arguments are handled in the manner of fmt.Print.
func Warning(v ...interface{}) {
	defaultLogger.output(sWarning, 0, fmt.Sprint(v...))
}

// WarningDepth acts as Warning but uses depth to determine which call frame to log.
// WarningDepth(0, "msg") is the same as Warning("msg").
func WarningDepth(depth int, v ...interface{}) {
	defaultLogger.output(sWarning, depth, fmt.Sprint(v...))
}

// Warningln uses the default logger and logs with the Warning severity.
// Arguments are handled in the manner of fmt.Println.
func Warningln(v ...interface{}) {
	defaultLogger.output(sWarning, 0, fmt.Sprintln(v...))
}

// Warningf uses the default logger and logs with the Warning severity.
// Arguments are handled in the manner of fmt.Printf.
func Warningf(format string, v ...interface{}) {
	defaultLogger.output(sWarning, 0, fmt.Sprintf(format, v...))
}

// Error uses the default logger and logs with the Error severity.
// Arguments are handled in the manner of fmt.Print.
func Error(v ...interface{}) {
	defaultLogger.output(sError, 0, fmt.Sprint(v...))
}

// ErrorDepth acts as Error but uses depth to determine which call frame to log.
// ErrorDepth(0, "msg") is the same as Error("msg").
func ErrorDepth(depth int, v ...interface{}) {
	defaultLogger.output(sError, depth, fmt.Sprint(v...))
}

// Errorln uses the default logger and logs with the Error severity.
// Arguments are handled in the manner of fmt.Println.
func Errorln(v ...interface{}) {
	defaultLogger.output(sError, 0, fmt.Sprintln(v...))
}

// Errorf uses the default logger and logs with the Error severity.
// Arguments are handled in the manner of fmt.Printf.
func Errorf(format string, v ...interface{}) {
	defaultLogger.output(sError, 0, fmt.Sprintf(format, v...))
}

// Fatalln uses the default logger, logs with the Fatal severity,
// and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Print.
func Fatal(v ...interface{}) {
	defaultLogger.output(sFatal, 0, fmt.Sprint(v...))
	defaultLogger.Close()
	os.Exit(1)
}

// FatalDepth acts as Fatal but uses depth to determine which call frame to log.
// FatalDepth(0, "msg") is the same as Fatal("msg").
func FatalDepth(depth int, v ...interface{}) {
	defaultLogger.output(sFatal, depth, fmt.Sprint(v...))
	defaultLogger.Close()
	os.Exit(1)
}

// Fatalln uses the default logger, logs with the Fatal severity,
// and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Println.
func Fatalln(v ...interface{}) {
	defaultLogger.output(sFatal, 0, fmt.Sprintln(v...))
	defaultLogger.Close()
	os.Exit(1)
}

// Fatalf uses the default logger, logs with the Fatal severity,
// and ends with os.Exit(1).
// Arguments are handled in the manner of fmt.Printf.
func Fatalf(format string, v ...interface{}) {
	defaultLogger.output(sFatal, 0, fmt.Sprintf(format, v...))
	defaultLogger.Close()
	os.Exit(1)
}

func toLogLine(calldepth int, s string) string {
	now := time.Now() // get this early.
	var file string
	var line int

	var ok bool
	_, file, line, ok = runtime.Caller(calldepth)
	if !ok {
		file = "???"
		line = 0
	}
	return fmt.Sprintf("%s %s:%d: %s", now.String(), file, line, s)
}

func toString(value interface{}) string {
	switch typedValue := value.(type) {
	case string:
		return typedValue
	case int:
		return strconv.Itoa(typedValue)
	case float64:
		return strconv.FormatFloat(typedValue, 'f', 6, 64)
	default:
		return fmt.Sprintf("%v", value)
	}
}

func (l *Logger) emitUnstructured(depth int, severity contracts.SeverityLevel, format interface{}, vars ...interface{}) {
	str := toString(format)
	str = toLogLine(depth, str)
	message := fmt.Sprintf(str, vars...)
	trace := appinsights.NewTraceTelemetry(message, severity)
	l.client.Track(trace)
}

func (l *Logger) emitStructured(depth int, severity contracts.SeverityLevel, message interface{}, vars ...interface{}) {
	str := toString(message)
	str = toLogLine(depth, str)
	trace := appinsights.NewTraceTelemetry(str, severity)

	// set properties
	for varIdx := 0; varIdx < len(vars); varIdx += 2 {
		key := toString(vars[varIdx])
		value := toString(vars[varIdx+1])

		trace.Properties[key] = value
	}

	l.client.Track(trace)
}
