GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
XRAY    ?= $(HOME)/soft/xray/xray
PKG     := ./...
BIN     := revhub
OUT     := out

.PHONY: all build release test vet verify demo serve clean fmt

all: vet test build

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/revhub

# Артефакты для install.sh (--repo): имена, которые ждёт скрипт.
release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/revhub-linux-amd64 ./cmd/revhub
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/revhub-linux-arm64 ./cmd/revhub
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/revhub-linux-armv7 ./cmd/revhub
	cd dist && sha256sum revhub-linux-* > SHA256SUMS
	@ls -lh dist/

test:
	$(GO) test $(PKG)

vet:
	$(GO) vet $(PKG)

# Проверка, что отрендеренный конфиг реально принимается ядром.
verify: demo
	./$(BIN) render --node hub     --state demo-state.json --out $(OUT)
	./$(BIN) render --node exit-eu --state demo-state.json --out $(OUT)
	$(XRAY) -test -c $(OUT)/hub/xray.json
	$(XRAY) -test -c $(OUT)/exit-eu/xray.json

demo:
	@test -f demo-state.json || ./$(BIN) demo --state demo-state.json

serve: build
	./$(BIN) serve --state demo-state.json --out $(OUT)

fmt:
	$(GO) fmt $(PKG)

clean:
	rm -rf $(OUT) $(BIN) demo-state.json dist
