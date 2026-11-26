package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nikolay-Jiang/shadowsocks-web/internal/agent"
	"github.com/Nikolay-Jiang/shadowsocks-web/internal/protocol"
)

func main() {
	configPath := flag.String("c", "/etc/shadowsocks-c/agent.json", "agent configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ss-agent %s\n", protocol.Version)
		return
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("ss-agent: ")

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("initialize: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Printf("run: %v", err)
		os.Exit(1)
	}
}
