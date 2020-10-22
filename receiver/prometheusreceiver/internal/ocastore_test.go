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

package internal

import (
	"context"
	"testing"

	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/scrape"
)

func TestOcaStore(t *testing.T) {
	ctx := context.Background()
	o := NewOcaStore(ctx, nil, nil, nil, false, "prometheus")

	app := o.Appender(ctx)
	if app != nil {
		t.Fatal("expecting nil, but got app")
	}

	o.SetScrapeManager(nil)
	app = o.Appender(ctx)
	if app != nil {
		t.Fatal("expecting error when ScrapeManager is not set, but got app")
	}

	o.SetScrapeManager(&scrape.Manager{})

	app = o.Appender(ctx)
	if app == nil {
		t.Fatalf("expecting app, but got nil\n")
	}

	_ = o.Close()

	app = o.Appender(ctx)
	if app != noop {
		t.Fatalf("expect app!=nil, got app=%v", app)
	}
}

func TestNoopAppender(t *testing.T) {
	if _, err := noop.Add(labels.FromStrings("t", "v"), 1, 1); err == nil {
		t.Error("expecting error from Add method of noopApender")
	}
	if _, err := noop.Add(labels.FromStrings("t", "v"), 1, 1); err == nil {
		t.Error("expecting error from Add method of noopApender")
	}

	if err := noop.AddFast(0, 1, 1); err == nil {
		t.Error("expecting error from AddFast method of noopApender")
	}

	if err := noop.Commit(); err == nil {
		t.Error("expecting error from Commit method of noopApender")
	}

	if err := noop.Rollback(); err != nil {
		t.Error("expecting no error from Rollback method of noopApender")
	}

}
