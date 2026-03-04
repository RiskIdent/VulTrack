package main

// Version is set at build time via -ldflags "-X main.Version=<version>".
// Falls back to "dev" when built without the flag (e.g. go run).
var Version = "dev"
