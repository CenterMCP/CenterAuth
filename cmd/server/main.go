package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/center/centerauth/internal/appversion"
	"github.com/center/centerauth/internal/auth"
)

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func main() {
	address := flag.String("address", net.JoinHostPort(env("HOST", "127.0.0.1"), env("PORT", "3002")), "HTTP listen address")
	publicURL := flag.String("public-url", env("BASE_URL", env("PUBLIC_URL", "http://127.0.0.1:3002")), "Public HTTPS base URL used as OAuth issuer (HTTP allowed on localhost)")
	database := flag.String("database", env("DATABASE_PATH", "build/centerauth.db"), "SQLite database file")
	allowedHosts := flag.String("allowed-hosts", env("ALLOWED_HOSTS", ""), "Comma-separated extra hostnames allowed for internal service requests")
	version := flag.Bool("version", false, "Print build version")
	flag.Parse()
	if *version {
		fmt.Println(appversion.String())
		return
	}
	if err := run(*address, *publicURL, *database, strings.Split(*allowedHosts, ",")...); err != nil {
		log.Fatal(err)
	}
}
func run(address, publicURL, database string, allowedHosts ...string) error {
	store, err := auth.Open(database)
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := auth.New(store, publicURL, appversion.String(), allowedHosts...)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: address, Handler: service.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
		if err := service.Transport.Shutdown(shutdown); err != nil {
			log.Printf("MCP shutdown: %v", err)
		}
	}()
	log.Printf("CenterAuth %s · MCP %s · demo %s", appversion.String(), service.Resource, service.Base+"/demo")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
