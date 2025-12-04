package main

import (
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const NumberOfMetrics = 800
const NumberOfScopedMetrics = 1
const NumberOfResourceMetrics = 4
const stepDuration time.Duration = 10 * time.Second
const defaultDuration time.Duration = 60 * time.Second

func CreateMetrics(mts pmetric.MetricSlice, startTime time.Time, duration time.Duration) {
	mts.EnsureCapacity(NumberOfMetrics)
	for idx := range NumberOfMetrics {
		mt := mts.AppendEmpty()
		mt.SetName("metric")
		datapoints := mt.SetEmptyGauge().DataPoints()

		nDatapoints := int((int64(duration) + (int64(stepDuration) - 1)) / int64(stepDuration))
		datapoints.EnsureCapacity(nDatapoints)

		sampleTime := startTime
		for range nDatapoints {
			datapoint := datapoints.AppendEmpty()
			datapoint.SetTimestamp(pcommon.NewTimestampFromTime(sampleTime))
			attrs := datapoint.Attributes()
			attrs.PutStr("route", fmt.Sprintf("/hello/%d", idx))
			attrs.PutStr("status", "200")
			sampleTime = sampleTime.Add(stepDuration)
		}
	}
}

func CreateManyScopedMetrics(rm pmetric.ResourceMetrics) {
	now := time.Date(2020, time.October, 30, 23, 0, 0, 0, time.UTC)
	sms := rm.ScopeMetrics()
	sms.EnsureCapacity(NumberOfScopedMetrics)
	for idx := range NumberOfScopedMetrics {
		scopeName := fmt.Sprintf("scope-%d", idx)

		sm := sms.AppendEmpty()
		scope := sm.Scope()
		scope.SetName(scopeName)
		attrs := scope.Attributes()
		attrs.PutStr("package", scopeName)

		metrics := sm.Metrics()
		CreateMetrics(metrics, now, defaultDuration)
	}
}

func CreateResourceMetrics(md pmetric.Metrics) {
	rms := md.ResourceMetrics()
	rms.EnsureCapacity(NumberOfResourceMetrics)
	for idx := range NumberOfResourceMetrics {
		rm := rms.AppendEmpty()
		attrs := rm.Resource().Attributes()
		attrs.PutStr("env", "dev")
		attrs.PutStr("region", "us-east-1")
		attrs.PutStr("pod", fmt.Sprintf("pod-%d", idx))
		CreateManyScopedMetrics(rm)
	}
}

