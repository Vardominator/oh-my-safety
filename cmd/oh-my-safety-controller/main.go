package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Vardominator/oh-my-safety/internal/controller"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("oh-my-safety-controller", flag.ContinueOnError)
	flags.SetOutput(stderr)
	databasePath := flags.String("db", "", "path to the controller SQLite database (required)")
	listenAddress := flags.String("listen", "", "listen address in host:port form (required)")
	tlsCertificate := flags.String("tls-cert", "", "TLS certificate path (required for non-loopback)")
	tlsKey := flags.String("tls-key", "", "TLS private-key path (required for non-loopback)")
	adminConfig := flags.String("admin-config", "", "mode-600 administrator JSON config path (required)")
	signingKey := flags.String("signing-key", "", "mode-600 persistent Ed25519 signing-key path (required)")
	bootstrap := flags.Bool("bootstrap", false, "initialize the administrator config and signing key, then exit")
	adminID := flags.String("admin-id", "initial-admin", "administrator id used with --bootstrap")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if *bootstrap {
		if *adminConfig == "" || *signingKey == "" {
			return errors.New("-admin-config and -signing-key are required with -bootstrap")
		}
		if *databasePath != "" || *listenAddress != "" ||
			*tlsCertificate != "" || *tlsKey != "" {
			return errors.New("server and TLS flags are not valid with -bootstrap")
		}
		signer, err := controller.LoadOrCreateSigner(*signingKey)
		if err != nil {
			return err
		}
		publicKey, err := signer.PublicKeyEncoded()
		if err != nil {
			return err
		}
		token, err := controller.InitializeAdminConfig(*adminConfig, *adminID)
		if err != nil {
			return err
		}
		return json.NewEncoder(stdout).Encode(controller.BootstrapResult{
			Schema:           "io.oh-my-safety/controller-bootstrap",
			SchemaVersion:    1,
			AdminID:          *adminID,
			AdminToken:       token,
			SigningPublicKey: publicKey,
		})
	}
	if *adminID != "initial-admin" {
		return errors.New("-admin-id is only valid with -bootstrap")
	}
	for name, value := range map[string]string{
		"db":           *databasePath,
		"listen":       *listenAddress,
		"admin-config": *adminConfig,
		"signing-key":  *signingKey,
	} {
		if value == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}
	if err := controller.ValidateListenConfiguration(
		*listenAddress,
		*tlsCertificate,
		*tlsKey,
	); err != nil {
		return err
	}

	principals, err := controller.LoadPrincipalSet(*adminConfig)
	if err != nil {
		return err
	}
	signer, err := controller.LoadOrCreateSigner(*signingKey)
	if err != nil {
		return err
	}
	store, err := controller.OpenStore(*databasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	api, err := controller.NewServer(store, principals, signer)
	if err != nil {
		return err
	}
	httpServer := controller.NewHTTPServer(*listenAddress, api.Handler())
	listenError := make(chan error, 1)
	go func() {
		fmt.Fprintf(stdout, "oh-my-safety controller listening on %s\n", *listenAddress)
		if *tlsCertificate != "" {
			listenError <- httpServer.ListenAndServeTLS(*tlsCertificate, *tlsKey)
			return
		}
		listenError <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-listenError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve controller: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("gracefully shut down controller: %w", err)
		}
		err := <-listenError
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve controller: %w", err)
		}
		return nil
	}
}
