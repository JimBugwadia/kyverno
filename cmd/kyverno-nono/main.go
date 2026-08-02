// Package main is the entry point for the kyverno-nono approval server.
// kyverno-nono implements the nono.sh approval webhook contract
// (POST /approve → {"decision":"granted"|"denied"}) backed by Kyverno
// ValidatingPolicies with evaluation mode "Nono".
package main

import (
	"fmt"
	"os"

	"github.com/kyverno/kyverno/cmd/kyverno-nono/internal"
	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	// Set up structured logging.
	ctrl.SetLogger(zap.New())

	root := &cobra.Command{
		Use:   "kyverno-nono",
		Short: "Kyverno-based approval server for nono.sh AI agent sandboxes",
		Long: `kyverno-nono implements the nono.sh external approval webhook contract.
It evaluates ValidatingPolicies (mode=Nono) to grant or deny approval
requests from nono.sh sandboxed agents, using Kyverno's CEL engine.`,
		SilenceUsage: true,
	}

	root.AddCommand(internal.ServeCommand())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
