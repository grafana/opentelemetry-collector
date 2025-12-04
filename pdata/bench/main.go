package main

import (
	"fmt"
	"runtime"
	"runtime/metrics"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
)

func kb(value uint64) float64 {
	return float64(value) / 1024
}

func main() {
	md := pmetric.NewMetrics()
	CreateResourceMetrics(md)
	exportReq := pmetricotlp.NewExportRequestFromMetrics(md)
	body, err := exportReq.MarshalProto()

	if err != nil {
		panic(err)
	}

	sampleBefore := []metrics.Sample{
		{
			Name: "/gc/heap/allocs:bytes",
		},
		{
			Name: "/gc/heap/frees:bytes",
		},
	}

	sampleAfter := []metrics.Sample{
		{
			Name: "/gc/heap/allocs:bytes",
		},
		{
			Name: "/gc/heap/frees:bytes",
		},
	}

	fmt.Printf("NumberOfMetrics:              %d\n", NumberOfMetrics)
	fmt.Printf("NumberOfScopedMetrics:        %d\n", NumberOfScopedMetrics)
	fmt.Printf("NumberOfResourceMetrics:      %d\n", NumberOfResourceMetrics)
	fmt.Printf("Marshalled size:              %d (%.2f KBs)\n", len(body), kb(uint64(len(body))))

	{
		metrics.Read(sampleBefore)
		res := pmetricotlp.NewExportRequestFromMetrics(md)
		err = res.UnmarshalProto(body)
		if err != nil {
			panic(err)
		}
		metrics.Read(sampleAfter)

		allocsBefore := sampleBefore[0].Value.Uint64()
		allocsAfter := sampleAfter[0].Value.Uint64()
		allocsDiff := allocsAfter - allocsBefore
		freesBefore := sampleBefore[1].Value.Uint64()
		freesAfter := sampleAfter[1].Value.Uint64()
		freesDiff := freesAfter - freesBefore

		fmt.Printf("\nDefault\n")
		fmt.Printf("Allocs (before, after, diff): %d (%.2f KBs), %d (%.2f KBs), %d (%.2f KBs)\n", allocsBefore, kb(allocsBefore), allocsAfter, kb(allocsAfter), allocsDiff, kb(allocsDiff))
		fmt.Printf("Frees (before, after, diff):  %d (%.2f KBs), %d (%.2f KBs), %d (%.2f KBs)\n", freesBefore, kb(freesBefore), freesAfter, kb(freesAfter), freesDiff, kb(freesDiff))
	}

	runtime.GC()

	{
		metrics.Read(sampleBefore)
		res := pmetricotlp.NewExportRequestFromMetrics(md)
		err = res.UnmarshalProtoLazy(body)
		if err != nil {
			panic(err)
		}
		metrics.Read(sampleAfter)

		allocsBefore := sampleBefore[0].Value.Uint64()
		allocsAfter := sampleAfter[0].Value.Uint64()
		allocsDiff := allocsAfter - allocsBefore
		freesBefore := sampleBefore[1].Value.Uint64()
		freesAfter := sampleAfter[1].Value.Uint64()
		freesDiff := freesAfter - freesBefore

		fmt.Printf("\nLazy\n")
		fmt.Printf("Allocs (before, after, diff): %d (%.2f KBs), %d (%.2f KBs), %d (%.2f KBs)\n", allocsBefore, kb(allocsBefore), allocsAfter, kb(allocsAfter), allocsDiff, kb(allocsDiff))
		fmt.Printf("Frees (before, after, diff):  %d (%.2f KBs), %d (%.2f KBs), %d (%.2f KBs)\n", freesBefore, kb(freesBefore), freesAfter, kb(freesAfter), freesDiff, kb(freesDiff))
	}
}
