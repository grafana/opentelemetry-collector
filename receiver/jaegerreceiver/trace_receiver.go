// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jaegerreceiver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"sync"

	apacheThrift "github.com/apache/thrift/lib/go/thrift"
	"github.com/gorilla/mux"
	"github.com/jaegertracing/jaeger/cmd/agent/app/configmanager"
	jSamplingConfig "github.com/jaegertracing/jaeger/cmd/agent/app/configmanager/grpc"
	"github.com/jaegertracing/jaeger/cmd/agent/app/httpserver"
	"github.com/jaegertracing/jaeger/cmd/agent/app/processors"
	"github.com/jaegertracing/jaeger/cmd/agent/app/servers"
	"github.com/jaegertracing/jaeger/cmd/agent/app/servers/thriftudp"
	"github.com/jaegertracing/jaeger/cmd/collector/app/handler"
	collectorSampling "github.com/jaegertracing/jaeger/cmd/collector/app/sampling"
	staticStrategyStore "github.com/jaegertracing/jaeger/plugin/sampling/strategystore/static"
	"github.com/jaegertracing/jaeger/proto-gen/api_v2"
	"github.com/jaegertracing/jaeger/thrift-gen/agent"
	"github.com/jaegertracing/jaeger/thrift-gen/baggage"
	"github.com/jaegertracing/jaeger/thrift-gen/jaeger"
	"github.com/jaegertracing/jaeger/thrift-gen/sampling"
	"github.com/jaegertracing/jaeger/thrift-gen/zipkincore"
	"github.com/uber/jaeger-lib/metrics"
	"go.uber.org/zap"
	"google.golang.org/grpc"

	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenterror"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/obsreport"
	jaegertranslator "go.opentelemetry.io/collector/translator/trace/jaeger"
)

var (
	batchSubmitNotOkResponse = &jaeger.BatchSubmitResponse{}
	batchSubmitOkResponse    = &jaeger.BatchSubmitResponse{Ok: true}
)

// Configuration defines the behavior and the ports that
// the Jaeger receiver will use.
type Configuration struct {
	CollectorThriftPort  int
	CollectorHTTPPort    int
	CollectorGRPCPort    int
	CollectorGRPCOptions []grpc.ServerOption

	AgentCompactThriftPort       int
	AgentBinaryThriftPort        int
	AgentHTTPPort                int
	RemoteSamplingClientSettings configgrpc.GRPCClientSettings
	RemoteSamplingStrategyFile   string
}

// Receiver type is used to receive spans that were originally intended to be sent to Jaeger.
// This receiver is basically a Jaeger collector.
type jReceiver struct {
	// mu protects the fields of this type
	mu sync.Mutex

	nextConsumer consumer.TraceConsumer
	instanceName string

	startOnce sync.Once
	stopOnce  sync.Once

	config *Configuration

	grpc            *grpc.Server
	collectorServer *http.Server

	agentSamplingManager *jSamplingConfig.SamplingManager
	agentProcessors      []processors.Processor
	agentServer          *http.Server

	logger *zap.Logger
}

const (
	defaultAgentQueueSize     = 1000
	defaultAgentMaxPacketSize = 65000
	defaultAgentServerWorkers = 10

	// Legacy metrics receiver name tag values
	collectorReceiverTagValue = "jaeger-collector"
	agentReceiverTagValue     = "jaeger-agent"

	agentTransportBinary   = "udp_thrift_binary"
	agentTransportCompact  = "udp_thrift_compact"
	collectorHTTPTransport = "collector_http"
	grpcTransport          = "grpc"

	thriftFormat   = "thrift"
	protobufFormat = "protobuf"
)

var (
	acceptedThriftFormats = map[string]struct{}{
		"application/x-thrift":                 {},
		"application/vnd.apache.thrift.binary": {},
	}
)

// New creates a TraceReceiver that receives traffic as a Jaeger collector, and
// also as a Jaeger agent.
func New(
	instanceName string,
	config *Configuration,
	nextConsumer consumer.TraceConsumer,
	params component.ReceiverCreateParams,
) (component.TraceReceiver, error) {
	return &jReceiver{
		config:       config,
		nextConsumer: nextConsumer,
		instanceName: instanceName,
		logger:       params.Logger,
	}, nil
}

func (jr *jReceiver) agentCompactThriftAddr() string {
	var port int
	if jr.config != nil {
		port = jr.config.AgentCompactThriftPort
	}
	return fmt.Sprintf(":%d", port)
}

func (jr *jReceiver) agentCompactThriftEnabled() bool {
	return jr.config != nil && jr.config.AgentCompactThriftPort > 0
}

func (jr *jReceiver) agentBinaryThriftAddr() string {
	var port int
	if jr.config != nil {
		port = jr.config.AgentBinaryThriftPort
	}
	return fmt.Sprintf(":%d", port)
}

func (jr *jReceiver) agentBinaryThriftEnabled() bool {
	return jr.config != nil && jr.config.AgentBinaryThriftPort > 0
}

func (jr *jReceiver) agentHTTPAddr() string {
	var port int
	if jr.config != nil {
		port = jr.config.AgentHTTPPort
	}
	return fmt.Sprintf(":%d", port)
}

func (jr *jReceiver) agentHTTPEnabled() bool {
	return jr.config != nil && jr.config.AgentHTTPPort > 0
}

func (jr *jReceiver) collectorGRPCAddr() string {
	var port int
	if jr.config != nil {
		port = jr.config.CollectorGRPCPort
	}
	return fmt.Sprintf(":%d", port)
}

func (jr *jReceiver) collectorGRPCEnabled() bool {
	return jr.config != nil && jr.config.CollectorGRPCPort > 0
}

func (jr *jReceiver) collectorHTTPAddr() string {
	var port int
	if jr.config != nil {
		port = jr.config.CollectorHTTPPort
	}
	return fmt.Sprintf(":%d", port)
}

func (jr *jReceiver) collectorHTTPEnabled() bool {
	return jr.config != nil && jr.config.CollectorHTTPPort > 0
}

func (jr *jReceiver) Start(ctx context.Context, host component.Host) error {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	var err = componenterror.ErrAlreadyStarted
	jr.startOnce.Do(func() {
		if err = jr.startAgent(host); err != nil && err != componenterror.ErrAlreadyStarted {
			jr.stopTraceReceptionLocked()
			return
		}

		if err = jr.startCollector(host); err != nil && err != componenterror.ErrAlreadyStarted {
			jr.stopTraceReceptionLocked()
			return
		}

		err = nil
	})
	return err
}

func (jr *jReceiver) Shutdown(context.Context) error {
	jr.mu.Lock()
	defer jr.mu.Unlock()

	return jr.stopTraceReceptionLocked()
}

func (jr *jReceiver) stopTraceReceptionLocked() error {
	var err = componenterror.ErrAlreadyStopped
	jr.stopOnce.Do(func() {
		var errs []error

		if jr.agentServer != nil {
			if aerr := jr.agentServer.Close(); aerr != nil {
				errs = append(errs, aerr)
			}
			jr.agentServer = nil
		}
		for _, processor := range jr.agentProcessors {
			processor.Stop()
		}

		if jr.collectorServer != nil {
			if cerr := jr.collectorServer.Close(); cerr != nil {
				errs = append(errs, cerr)
			}
			jr.collectorServer = nil
		}
		if jr.grpc != nil {
			jr.grpc.Stop()
			jr.grpc = nil
		}
		if len(errs) == 0 {
			err = nil
			return
		}
		// Otherwise combine all these errors
		buf := new(bytes.Buffer)
		for _, err := range errs {
			fmt.Fprintf(buf, "%s\n", err.Error())
		}
		err = errors.New(buf.String())
	})

	return err
}

func consumeTraces(
	ctx context.Context,
	batches []*jaeger.Batch,
	consumer consumer.TraceConsumer,
) ([]*jaeger.BatchSubmitResponse, int, error) {

	jbsr := make([]*jaeger.BatchSubmitResponse, 0, len(batches))
	var consumerError error
	numSpans := 0
	for _, batch := range batches {
		numSpans += len(batch.Spans)
		if consumerError != nil {
			jbsr = append(jbsr, batchSubmitNotOkResponse)
			continue
		}

		td := jaegertranslator.ThriftBatchToInternalTraces(batch)
		consumerError = consumer.ConsumeTraces(ctx, td)
		jsr := batchSubmitOkResponse
		if consumerError != nil {
			jsr = batchSubmitNotOkResponse
		}
		jbsr = append(jbsr, jsr)
	}

	return jbsr, numSpans, consumerError
}

var _ agent.Agent = (*agentHandler)(nil)
var _ api_v2.CollectorServiceServer = (*jReceiver)(nil)
var _ configmanager.ClientConfigManager = (*jReceiver)(nil)

type agentHandler struct {
	name         string
	transport    string
	ctx          context.Context
	nextConsumer consumer.TraceConsumer
}

func (h *agentHandler) EmitZipkinBatch(ctx context.Context, spans []*zipkincore.Span) error {
	// TODO(rfratto): impl
	return fmt.Errorf("NYI")
}

// EmitBatch implements cmd/agent/reporter.Reporter and it forwards
// Jaeger spans received by the Jaeger agent processor.
func (h *agentHandler) EmitBatch(_ context.Context, batch *jaeger.Batch) error {
	ctx := obsreport.StartTraceDataReceiveOp(
		h.ctx, h.name, h.transport)

	td := jaegertranslator.ThriftBatchToInternalTraces(batch)

	err := h.nextConsumer.ConsumeTraces(ctx, td)
	obsreport.EndTraceDataReceiveOp(ctx, thriftFormat, len(batch.Spans), err)

	return err
}

func (jr *jReceiver) GetSamplingStrategy(ctx context.Context, serviceName string) (*sampling.SamplingStrategyResponse, error) {
	return jr.agentSamplingManager.GetSamplingStrategy(ctx, serviceName)
}

func (jr *jReceiver) GetBaggageRestrictions(ctx context.Context, serviceName string) ([]*baggage.BaggageRestriction, error) {
	br, err := jr.agentSamplingManager.GetBaggageRestrictions(ctx, serviceName)
	if err != nil {
		// Baggage restrictions are not yet implemented - refer to - https://github.com/jaegertracing/jaeger/issues/373
		// As of today, GetBaggageRestrictions() always returns an error.
		// However, we `return nil, nil` here in order to serve a valid `200 OK` response.
		return nil, nil
	}
	return br, nil
}

func (jr *jReceiver) PostSpans(ctx context.Context, r *api_v2.PostSpansRequest) (*api_v2.PostSpansResponse, error) {
	if c, ok := client.FromGRPC(ctx); ok {
		ctx = client.NewContext(ctx, c)
	}

	ctx = obsreport.ReceiverContext(
		ctx, jr.instanceName, grpcTransport, collectorReceiverTagValue)
	ctx = obsreport.StartTraceDataReceiveOp(ctx, jr.instanceName, grpcTransport)

	td := jaegertranslator.ProtoBatchToInternalTraces(r.GetBatch())

	err := jr.nextConsumer.ConsumeTraces(ctx, td)
	obsreport.EndTraceDataReceiveOp(ctx, protobufFormat, len(r.GetBatch().Spans), err)
	if err != nil {
		return nil, err
	}

	return &api_v2.PostSpansResponse{}, nil
}

func (jr *jReceiver) startAgent(_ component.Host) error {
	if !jr.agentBinaryThriftEnabled() && !jr.agentCompactThriftEnabled() && !jr.agentHTTPEnabled() {
		return nil
	}

	if jr.agentBinaryThriftEnabled() {
		h := &agentHandler{
			name:         jr.instanceName,
			transport:    agentTransportBinary,
			nextConsumer: jr.nextConsumer,
			ctx: obsreport.ReceiverContext(
				context.Background(), jr.instanceName, agentTransportBinary, agentReceiverTagValue),
		}
		processor, err := jr.buildProcessor(jr.agentBinaryThriftAddr(), apacheThrift.NewTBinaryProtocolFactoryDefault(), h)
		if err != nil {
			return err
		}
		jr.agentProcessors = append(jr.agentProcessors, processor)
	}

	if jr.agentCompactThriftEnabled() {
		h := &agentHandler{
			name:         jr.instanceName,
			transport:    agentTransportCompact,
			nextConsumer: jr.nextConsumer,
			ctx: obsreport.ReceiverContext(
				context.Background(), jr.instanceName, agentTransportCompact, agentReceiverTagValue),
		}
		processor, err := jr.buildProcessor(jr.agentCompactThriftAddr(), apacheThrift.NewTCompactProtocolFactory(), h)
		if err != nil {
			return err
		}
		jr.agentProcessors = append(jr.agentProcessors, processor)
	}

	for _, processor := range jr.agentProcessors {
		go processor.Serve()
	}

	// Start upstream grpc client before serving sampling endpoints over HTTP
	if jr.config.RemoteSamplingClientSettings.Endpoint != "" {
		grpcOpts, err := configgrpc.GrpcSettingsToDialOptions(jr.config.RemoteSamplingClientSettings)
		if err != nil {
			jr.logger.Error("Error creating grpc dial options for remote sampling endpoint", zap.Error(err))
			return err
		}
		conn, err := grpc.Dial(jr.config.RemoteSamplingClientSettings.Endpoint, grpcOpts...)
		if err != nil {
			jr.logger.Error("Error creating grpc connection to jaeger remote sampling endpoint", zap.String("endpoint", jr.config.RemoteSamplingClientSettings.Endpoint))
			return err
		}

		jr.agentSamplingManager = jSamplingConfig.NewConfigManager(conn)
	}

	if jr.agentHTTPEnabled() {
		jr.agentServer = httpserver.NewHTTPServer(jr.agentHTTPAddr(), jr, metrics.NullFactory)

		go func() {
			if err := jr.agentServer.ListenAndServe(); err != nil {
				jr.logger.Error("http server failure", zap.Error(err))
			}
		}()
	}

	return nil
}

func (jr *jReceiver) buildProcessor(address string, factory apacheThrift.TProtocolFactory, jaegerAgent agent.Agent) (processors.Processor, error) {
	handler := agent.NewAgentProcessor(jaegerAgent)
	transport, err := thriftudp.NewTUDPServerTransport(address)
	if err != nil {
		return nil, err
	}
	server, err := servers.NewTBufferedServer(transport, defaultAgentQueueSize, defaultAgentMaxPacketSize, metrics.NullFactory)
	if err != nil {
		return nil, err
	}
	processor, err := processors.NewThriftProcessor(server, defaultAgentServerWorkers, metrics.NullFactory, factory, handler, jr.logger)
	if err != nil {
		return nil, err
	}
	return processor, nil
}

func (jr *jReceiver) decodeThriftHTTPBody(r *http.Request) (*jaeger.Batch, *httpError) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, &httpError{
			handler.UnableToReadBodyErrFormat,
			http.StatusInternalServerError,
		}
	}

	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, &httpError{
			fmt.Sprintf("Cannot parse content type: %v", err),
			http.StatusBadRequest,
		}
	}
	if _, ok := acceptedThriftFormats[contentType]; !ok {
		return nil, &httpError{
			fmt.Sprintf("Unsupported content type: %v", contentType),
			http.StatusBadRequest,
		}
	}

	tdes := apacheThrift.NewTDeserializer()
	batch := &jaeger.Batch{}
	if err = tdes.Read(batch, bodyBytes); err != nil {
		return nil, &httpError{
			fmt.Sprintf(handler.UnableToReadBodyErrFormat, err),
			http.StatusBadRequest,
		}
	}
	return batch, nil
}

// HandleThriftHTTPBatch implements Jaeger HTTP Thrift handler.
func (jr *jReceiver) HandleThriftHTTPBatch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if c, ok := client.FromHTTP(r); ok {
		ctx = client.NewContext(ctx, c)
	}

	ctx = obsreport.ReceiverContext(
		ctx, jr.instanceName, collectorHTTPTransport, collectorReceiverTagValue)
	ctx = obsreport.StartTraceDataReceiveOp(
		ctx, jr.instanceName, collectorHTTPTransport)

	batch, hErr := jr.decodeThriftHTTPBody(r)
	if hErr != nil {
		http.Error(w, hErr.msg, hErr.statusCode)
		obsreport.EndTraceDataReceiveOp(ctx, thriftFormat, 0, hErr)
		return
	}

	_, numSpans, err := consumeTraces(ctx, []*jaeger.Batch{batch}, jr.nextConsumer)
	if err != nil {
		http.Error(w, fmt.Sprintf("Cannot submit Jaeger batch: %v", err), http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusAccepted)
	}
	obsreport.EndTraceDataReceiveOp(ctx, thriftFormat, numSpans, err)
}

func (jr *jReceiver) startCollector(host component.Host) error {
	if !jr.collectorGRPCEnabled() && !jr.collectorHTTPEnabled() {
		return nil
	}

	if jr.collectorHTTPEnabled() {
		// Now the collector that runs over HTTP
		caddr := jr.collectorHTTPAddr()
		cln, cerr := net.Listen("tcp", caddr)
		if cerr != nil {
			return fmt.Errorf("failed to bind to Collector address %q: %v", caddr, cerr)
		}

		nr := mux.NewRouter()
		nr.HandleFunc("/api/traces", jr.HandleThriftHTTPBatch).Methods(http.MethodPost)
		jr.collectorServer = &http.Server{Handler: nr}
		go func() {
			_ = jr.collectorServer.Serve(cln)
		}()
	}

	if jr.collectorGRPCEnabled() {
		jr.grpc = grpc.NewServer(jr.config.CollectorGRPCOptions...)
		gaddr := jr.collectorGRPCAddr()
		gln, gerr := net.Listen("tcp", gaddr)
		if gerr != nil {
			return fmt.Errorf("failed to bind to gRPC address %q: %v", gaddr, gerr)
		}

		api_v2.RegisterCollectorServiceServer(jr.grpc, jr)

		// init and register sampling strategy store
		ss, gerr := staticStrategyStore.NewStrategyStore(staticStrategyStore.Options{
			StrategiesFile: jr.config.RemoteSamplingStrategyFile,
		}, jr.logger)
		if gerr != nil {
			return fmt.Errorf("failed to create collector strategy store: %v", gerr)
		}
		api_v2.RegisterSamplingManagerServer(jr.grpc, collectorSampling.NewGRPCHandler(ss))

		go func() {
			if err := jr.grpc.Serve(gln); err != nil {
				host.ReportFatalError(err)
			}
		}()
	}

	return nil
}
