package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"text/tabwriter"

	"github.com/whtsky/clash/config"
	C "github.com/whtsky/clash/constant"
	"github.com/whtsky/clash/hub"
	"github.com/whtsky/clash/hub/executor"
	"github.com/whtsky/clash/log"
	"github.com/whtsky/clash/tunnel"
)

var (
	flagset            map[string]bool
	version            bool
	testConfig         bool
	ruleInspect        bool
	homeDir            string
	configFile         string
	externalUI         string
	externalController string
	secret             string
)

func init() {
	flag.StringVar(&homeDir, "d", "", "set configuration directory")
	flag.StringVar(&configFile, "f", "", "specify configuration file")
	flag.StringVar(&externalUI, "ext-ui", "", "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", "", "override external controller address")
	flag.StringVar(&secret, "secret", "", "override secret for RESTful API")
	flag.BoolVar(&version, "v", false, "show current version of clash")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.BoolVar(&ruleInspect, "rule-inspect", false, "show counts of different rule types")
	flag.Parse()

	flagset = map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		flagset[f.Name] = true
	})
}

func countRules(rules []C.Rule) map[C.RuleType]int {
	counts := make(map[C.RuleType]int)
	for _, rule := range rules {
		ruleType := rule.RuleType()
		_, ok := counts[ruleType]
		if !ok {
			counts[ruleType] = 1
		} else {
			counts[ruleType]++
		}
	}
	return counts
}

func printRuleCounts(rules []C.Rule) {
	result := countRules(rules)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 5, ' ', 0)
	for ruleType, count := range result {
		fmt.Fprintf(w, "%s\t%d\n", ruleType, count)
	}
	w.Flush()
}

func printRuleInspect(rules []C.Rule) {
	fmt.Println("========== Raw Rules ==========")
	printRuleCounts(rules)
	fmt.Println("\n\n========== Combined Rules ==========")
	printRuleCounts(tunnel.CombineRules(rules))
}

func main() {
	if version {
		fmt.Printf("Clash %s %s %s with %s %s\n", C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		return
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if configFile != "" {
		if !filepath.IsAbs(configFile) {
			currentDir, _ := os.Getwd()
			configFile = filepath.Join(currentDir, configFile)
		}
		C.SetConfig(configFile)
	} else {
		configFile := filepath.Join(C.Path.HomeDir(), C.Path.Config())
		C.SetConfig(configFile)
	}

	if err := config.Init(C.Path.HomeDir()); err != nil {
		log.Fatalln("Initial configuration directory error: %s", err.Error())
	}

	if testConfig {
		config, err := executor.Parse()
		if err != nil {
			log.Errorln(err.Error())
			fmt.Printf("configuration file %s test failed\n", C.Path.Config())
			os.Exit(1)
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		if ruleInspect {
			printRuleInspect(config.Rules)
		}
		return
	}

	if ruleInspect {
		config, err := executor.Parse()
		if err != nil {
			log.Errorln(err.Error())
			os.Exit(1)
		}
		printRuleInspect(config.Rules)
	}

	var options []hub.Option
	if flagset["ext-ui"] {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if flagset["ext-ctl"] {
		options = append(options, hub.WithExternalController(externalController))
	}
	if flagset["secret"] {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
