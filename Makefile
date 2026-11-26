GO ?= go
BIN ?= bin

.PHONY: all panel agent test vet fmt clean

all: panel agent

panel:
	mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $(BIN)/ss-panel ./cmd/ss-panel

agent:
	mkdir -p $(BIN)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $(BIN)/ss-agent ./cmd/ss-agent

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

clean:
	rm -rf $(BIN)
