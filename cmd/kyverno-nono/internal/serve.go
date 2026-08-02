// Package internal contains the serve sub-command for kyverno-nono.
package internal

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cespare/xxhash/v2"
	vpol "github.com/kyverno/api/api/policies.kyverno.io/v1"
	authzsources "github.com/kyverno/kyverno-authz/pkg/engine/sources"
	"github.com/kyverno/kyverno-authz/pkg/events"
	"github.com/kyverno/kyverno-authz/pkg/probes"
	"github.com/kyverno/kyverno-authz/pkg/server"
	"github.com/kyverno/kyverno-authz/pkg/signals"
	authzutils "github.com/kyverno/kyverno-authz/pkg/utils"
	"github.com/kyverno/kyverno-authz/pkg/utils/ocifs"
	approvehandler "github.com/kyverno/kyverno/cmd/kyverno-nono/handlers"
	nonotype "github.com/kyverno/kyverno/pkg/cel/libs/authz/nono"
	nononcompiler "github.com/kyverno/kyverno/pkg/nono/compiler"
	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/dispatchers"
	sdkhandlers "github.com/kyverno/sdk/core/handlers"
	"github.com/kyverno/sdk/core/resulters"
	sdksources "github.com/kyverno/sdk/core/sources"
	sdkpolicy "github.com/kyverno/sdk/extensions/policy"
	openreportsclient "github.com/openreports/reports-api/pkg/client/clientset/versioned/typed/openreports.io/v1alpha1"
	"github.com/spf13/cobra"
	"go.uber.org/multierr"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// NonoPolicy is the concrete compiled policy type used by the nono engine.
type NonoPolicy = nononcompiler.CompiledPolicy

// ServeCommand returns the `serve` cobra sub-command.
func ServeCommand() *cobra.Command {
	var (
		serverAddress         string
		probesAddress         string
		metricsAddress        string
		certFile              string
		keyFile               string
		kubePolicySource      bool
		externalPolicySources []string
		imagePullSecrets      []string
		allowInsecureRegistry bool
		eventsEnabled         bool
		openreportsEnabled    bool
		reportFlushInterval   string
		resultBufSize         int
		msgFormat             string
		kubeConfigOverrides   clientcmd.ConfigOverrides
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the kyverno-nono approval webhook server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return signals.Do(context.Background(), func(ctx context.Context) error {
				var probesErr, serverErr, mgrErr error
				err := func(ctx context.Context) error {
					logger := ctrl.LoggerFrom(ctx)

					// Build kubeconfig (optional — degrades gracefully).
					kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
						clientcmd.NewDefaultClientConfigLoadingRules(),
						&kubeConfigOverrides,
					)
					config, cfgErr := kubeConfig.ClientConfig()
					kubeOk := cfgErr == nil

					if !kubeOk {
						logger.Info("No Kubernetes cluster configuration found; running in standalone mode (filesystem policies only)")
					}

					ctx, cancel := context.WithCancel(ctx)
					defer cancel()

					var group wait.Group
					defer group.Wait()

					// Build event subscribers.
					var eventHandlers []events.EventIface[nonotype.CheckRequest]
					eventHandlers = append(eventHandlers, events.NewWriterEventSubscriber[nonotype.CheckRequest](
						os.Stdout, logger, msgFormat,
					))

					// Set up nono compiler.
					// We always use a kyverno-authz compiler but parameterised on
					// nono.CheckRequest / nono.CheckResponse types.
					// The compiler must know about the Nono CEL env.
					// We wrap the upstream generic compiler with our env factory below.
					var nonoCompiler *nononcompiler.Compiler
					var dyn dynamic.Interface
					var source core.Source[NonoPolicy]

					if kubeOk {
						kubeclient, err := kubernetes.NewForConfig(config)
						if err != nil {
							return fmt.Errorf("building kube client: %w", err)
						}
						dynclient, err := dynamic.NewForConfig(config)
						if err != nil {
							return fmt.Errorf("building dynamic client: %w", err)
						}
						dyn = dynclient
						nonoCompiler = newNonoCompiler(dynclient)

						namespace, _, err := kubeConfig.Namespace()
						if err != nil {
							return fmt.Errorf("getting namespace: %w", err)
						}
						if namespace == "" || namespace == "default" {
							logger.Info(fmt.Sprintf("Using namespace '%s' for events/reports", namespace))
						}

						if eventsEnabled {
							eventHandlers = append(eventHandlers, events.NewK8sEventSubscriber[nonotype.CheckRequest](
								ctx, kubeclient, namespace, logger, msgFormat,
							))
						}

						if openreportsEnabled {
							if exists, err := authzutils.CrdExists(config, "reports.openreports.io"); err != nil {
								logger.Error(err, "checking for openreports CRD")
							} else if exists {
								orClient, err := openreportsclient.NewForConfig(config)
								if err != nil {
									logger.Error(err, "building openreports client")
								} else {
									var intervalPtr *time.Duration
									if d, err := time.ParseDuration(reportFlushInterval); err == nil {
										intervalPtr = &d
									}
									reportName := "nono-approvals-report"
									if pod := os.Getenv("POD_NAME"); pod != "" {
										reportName = fmt.Sprintf("%s-%x", reportName, xxhash.Sum64String(pod))
									}
									eventHandlers = append(eventHandlers, events.NewOpenreportsSubscriber[nonotype.CheckRequest](
										ctx, resultBufSize, orClient, intervalPtr, logger,
										reportName, namespace, msgFormat,
									))
								}
							}
						}

						rOpts, nOpts, err := ocifs.RegistryOpts(kubeclient.CoreV1().Secrets(namespace), allowInsecureRegistry, imagePullSecrets...)
						if err != nil {
							return fmt.Errorf("initialising registry options: %w", err)
						}
						extSources, err := authzutils.GetExternalSources(nonoCompiler, nOpts, rOpts, externalPolicySources...)
						if err != nil {
							return err
						}
						source = sdksources.NewComposite(extSources...)

						if kubePolicySource {
							scheme := runtime.NewScheme()
							if err := vpol.Install(scheme); err != nil {
								return err
							}
							mgr, err := ctrl.NewManager(config, ctrl.Options{
								Scheme: scheme,
								Metrics: metricsserver.Options{
									BindAddress: metricsAddress,
								},
								Cache: cache.Options{
									ByObject: map[client.Object]cache.ByObject{
										&vpol.ValidatingPolicy{}: {
											Field: fields.OneTermEqualSelector("spec.evaluation.mode", string(nonotype.EvaluationModeNono)),
										},
									},
								},
							})
							if err != nil {
								return fmt.Errorf("constructing manager: %w", err)
							}
							kubeSource, err := authzsources.NewKube("nono", mgr, nonoCompiler)
							if err != nil {
								return fmt.Errorf("creating nono kube source: %w", err)
							}
							source = sdksources.NewComposite(kubeSource, source)
							group.StartWithContext(ctx, func(ctx context.Context) {
								defer cancel()
								mgrErr = mgr.Start(ctx)
							})
							if !mgr.GetCache().WaitForCacheSync(ctx) {
								defer cancel()
								return fmt.Errorf("failed to wait for nono policy cache sync")
							}
						}
					} else {
						// Standalone mode: no cluster.
						nonoCompiler = newNonoCompiler(nil)
						rOpts, nOpts, err := ocifs.RegistryOpts(nil, allowInsecureRegistry)
						if err != nil {
							return fmt.Errorf("initialising registry options: %w", err)
						}
						extSources, err := authzutils.GetExternalSources(nonoCompiler, nOpts, rOpts, externalPolicySources...)
						if err != nil {
							return err
						}
						source = sdksources.NewComposite(extSources...)
					}

					// Build engine.
					eng := core.NewEngine(
						source,
						sdkhandlers.Handler(
							dispatchers.Sequential(
								sdkpolicy.EvaluatorFactory[NonoPolicy](),
								func(ctx context.Context, fc core.FactoryContext[NonoPolicy, dynamic.Interface, *nonotype.CheckRequest]) core.Breaker[NonoPolicy, *nonotype.CheckRequest, sdkpolicy.Evaluation[*nonotype.CheckResponse]] {
									return core.MakeBreakerFunc(func(_ context.Context, _ NonoPolicy, _ *nonotype.CheckRequest, out sdkpolicy.Evaluation[*nonotype.CheckResponse]) bool {
										return out.Result != nil
									})
								},
							),
							func(ctx context.Context, fc core.FactoryContext[NonoPolicy, dynamic.Interface, *nonotype.CheckRequest]) core.Resulter[NonoPolicy, *nonotype.CheckRequest, sdkpolicy.Evaluation[*nonotype.CheckResponse], sdkpolicy.Evaluation[*nonotype.CheckResponse]] {
								return resulters.NewFirst[NonoPolicy, *nonotype.CheckRequest](func(out sdkpolicy.Evaluation[*nonotype.CheckResponse]) bool {
									return out.Result != nil || out.Error != nil
								})
							},
						),
					)

					ev := events.NewComposite(eventHandlers...)

					// Probes server.
					if probesAddress != "" {
						group.StartWithContext(ctx, func(ctx context.Context) {
							defer cancel()
							probesErr = probes.NewServer(probesAddress).Run(ctx)
						})
					}

					// Main approval server.
					approvalServer := newApprovalServer(serverAddress, certFile, keyFile, eng, dyn, ev)
					group.StartWithContext(ctx, func(ctx context.Context) {
						defer cancel()
						serverErr = approvalServer.Run(ctx)
					})

					return nil
				}(ctx)
				return multierr.Combine(err, probesErr, serverErr, mgrErr)
			})
		},
	}

	cmd.Flags().StringVar(&serverAddress, "address", ":8765", "Address for the approval webhook server (default :8765 matches nono demo)")
	cmd.Flags().StringVar(&probesAddress, "probes-address", ":8080", "Address for /livez and /readyz probes")
	cmd.Flags().StringVar(&metricsAddress, "metrics-address", ":9082", "Address for Prometheus metrics")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "TLS certificate file (optional)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "TLS key file (optional)")
	cmd.Flags().BoolVar(&kubePolicySource, "kube-policy-source", true, "Watch ValidatingPolicies from the cluster")
	cmd.Flags().StringArrayVar(&externalPolicySources, "external-policy-source", nil, "Filesystem or OCI policy sources (e.g. file:///policies or oci://...)")
	cmd.Flags().StringArrayVar(&imagePullSecrets, "image-pull-secret", nil, "Image pull secrets for OCI policy sources")
	cmd.Flags().BoolVar(&allowInsecureRegistry, "allow-insecure-registry", false, "Allow insecure OCI registries")
	cmd.Flags().BoolVar(&eventsEnabled, "events-enabled", false, "Emit Kubernetes Events for each decision")
	cmd.Flags().BoolVar(&openreportsEnabled, "openreports-enabled", false, "Write decisions to an OpenReports CR")
	cmd.Flags().StringVar(&reportFlushInterval, "report-flush-interval", "", "Flush interval for OpenReports (e.g. 30s)")
	cmd.Flags().IntVar(&resultBufSize, "result-buffer-size", 500, "OpenReports ring-buffer size")
	cmd.Flags().StringVar(&msgFormat, "log-msg-format", "[%s] nono: request %s, decision: %s\n", "stdout log format")
	clientcmd.BindOverrideFlags(&kubeConfigOverrides, cmd.Flags(), clientcmd.RecommendedConfigOverrideFlags("kube-"))
	return cmd
}

// newNonoCompiler creates a nono policy compiler.
func newNonoCompiler(dyn dynamic.Interface) *nononcompiler.Compiler {
	return nononcompiler.NewCompiler(dyn)
}

// newApprovalServer wires up the HTTP mux with POST /approve.
func newApprovalServer(
	addr, certFile, keyFile string,
	eng core.Engine[dynamic.Interface, *nonotype.CheckRequest, sdkpolicy.Evaluation[*nonotype.CheckResponse]],
	dyn dynamic.Interface,
	ev events.EventIface[nonotype.CheckRequest],
) server.ServerFunc {
	return func(ctx context.Context) error {
		mux := http.NewServeMux()
		authorizer := approvehandler.NewAuthorizer(eng, dyn, ev)
		mux.Handle("POST /approve", authorizer)

		s := &http.Server{
			Addr:    addr,
			Handler: mux,
		}
		if certFile != "" && keyFile != "" {
			s.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				},
			}
		}
		return server.RunHttp(ctx, s, certFile, keyFile)
	}
}
