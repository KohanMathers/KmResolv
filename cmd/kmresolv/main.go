package main

import (
	"fmt"
	"os"
)

var Version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "flush":
		cmdFlush(os.Args[2:])
	case "block":
		cmdBlock(os.Args[2:])
	case "unblock":
		cmdUnblock(os.Args[2:])
	case "log":
		cmdLog(os.Args[2:])
	case "version":
		fmt.Println("kmresolv v" + Version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`kmresolv — a recursive DNS resolver

Usage:
  kmresolv serve [--config path]     start the DNS server
  kmresolv status [flags]            show resolver stats
  kmresolv flush [--expired|--negative]  flush the cache
  kmresolv block <domain>            add domain to blocklist
  kmresolv unblock <domain>          remove domain from blocklist
  kmresolv log [--n 50]              show recent query log
  kmresolv version                   print version

Flags (all CLI commands):
  --host string    dashboard host (default: from config or 127.0.0.1)
  --port int       dashboard port (default: from config or 8080)
  --config string  path to config file (default: config.yml)
`)
}
