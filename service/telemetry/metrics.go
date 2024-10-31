// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry // import "go.opentelemetry.io/collector/service/telemetry"

import (
	"context"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"go.opentelemetry.io/collector/service/telemetry/internal/otelinit"
)

type meterProvider struct {
	*sdkmetric.MeterProvider
}

type meterProviderSettings struct {
	res               *resource.Resource
	asyncErrorChannel chan error

	OtelMetricViews  []sdkmetric.View
	OtelMetricReader sdkmetric.Reader
}

func newMeterProvider(set meterProviderSettings, disableHighCardinality bool) (metric.MeterProvider, error) {
	mp := &meterProvider{}
	opts := []sdkmetric.Option{
		sdkmetric.WithReader(set.OtelMetricReader),
		sdkmetric.WithView(set.OtelMetricViews...),
	}

	var err error
	mp.MeterProvider, err = otelinit.InitOpenTelemetry(set.res, opts, disableHighCardinality)
	if err != nil {
		return nil, err
	}
	return mp, nil
}

// Shutdown the meter provider and all the associated resources.
// The type signature of this method matches that of the sdkmetric.MeterProvider.
func (mp *meterProvider) Shutdown(_ context.Context) error {
	return nil
}
