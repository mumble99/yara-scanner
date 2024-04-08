package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Codehardt/go-cpulimit"
	"github.com/hillu/go-yara/v4"
	"github.com/shirou/gopsutil/v3/process"
)

func logIfMatch(item string, m []yara.MatchRule, err error) {
	if err != nil {
		return
	}
	if len(m) == 0 {
		return
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
}


func procScan(rules *yara.Rules) {
	s, _ := yara.NewScanner(rules)
	proceses, _ := process.Processes()
	currentPid := os.Getpid()
	for _, proc := range proceses {
		pid := int(proc.Pid)
		if currentPid != pid {
			var m yara.MatchRules
			var exe string
			log.Printf("Scanning process id %d", pid)
			err := s.SetCallback(&m).ScanProc(pid)
			exe, _ = proc.Exe()
			logIfMatch(fmt.Sprintf("process %s pid %d", exe, pid), m, err)
		}
	}
}

func fileSystemScan(rules *yara.Rules, excluded []string) {
	s, _ := yara.NewScanner(rules)
	path := "/"
	if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			if !contains(excluded, path) {
				var m yara.MatchRules
				log.Printf("Scanning file %s", path)
				err := s.SetCallback(&m).ScanFile(path)
				logIfMatch(path, m, err)
			}
		} else if info.Mode().IsDir() {
			return nil
		}
		return nil
	}); err != nil {
		log.Printf("walk: %s: %s", path, err)
	}
}

func main() {
	var (
		rules             rules
		processScan       bool
		cpuLimit          int
		excludedDirString string
		excludedDir       []string
	)

	flag.BoolVar(&processScan, "processes", false, "scan processes")
	flag.IntVar(&cpuLimit, "limit", -1, "upper limit on CPU usage. Disabled by default")
	flag.StringVar(&excludedDirString, "exclude", "NOTHING", "exclude directory from scanning. Example: /etc/apache2,/proc")
	flag.Var(&rules, "rule", "path to rule")

	flag.Parse()

	if len(rules) == 0 {
		flag.Usage()
		log.Fatal("no rules specified")
	}

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize yara-scanner compiler: %s", err)
	}

	for _, rule := range rules {
		f, err := os.Open(rule.filename)
		if err != nil {
			log.Fatalf("Could not open rule file %s: %s", rule.filename, err)
		}
		err = c.AddFile(f, rule.namespace)
		f.Close()
		if err != nil {
			log.Fatalf("Could not parse rule file %s: %s", rule.filename, err)
		}
	}

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}
	excludedDir = strings.Split(excludedDirString, ",")
	if cpuLimit != -1 {
		limiter := &cpulimit.Limiter{
			MaxCPUUsage:     float64(cpuLimit),
			MeasureInterval: time.Millisecond * 200,
			Measurements:    3,
		}
		limiter.Start()
		defer limiter.Stop()
		for {
			limiter.Wait()
			if processScan {
				procScan(r)
			}
			fileSystemScan(r, excludedDir)
		}
	} else {
		if processScan {
			procScan(r)
		}
		fileSystemScan(r, excludedDir)
	}
}
