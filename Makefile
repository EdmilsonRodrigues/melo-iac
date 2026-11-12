BINARY  := auth
BIN_DIR := bin
CMD     := ./auth/cmd/http
# Um ./<modulo>/... por go.mod: a raiz nao e um modulo, entao ./... nao casa nada.
PKGS    ?= $(patsubst %/go.mod,./%/...,$(wildcard */go.mod))

FUZZ_PKG  ?=
FUZZ      ?=
FUZZTIME  ?= 30s

BENCH_COUNT ?= 10
BENCH_OUT   ?= bench.txt

OLD ?= old.txt
NEW ?= new.txt

.DEFAULT_GOAL := help
.PHONY: help work fmt build lint test bench fuzz stress cover benchcmp

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  work       Cria/atualiza o go.work com todos os modulos do repo"
	@echo "  fmt        Formata o codigo (gofmt + goimports via golangci-lint)"
	@echo "  build      Compila $(BIN_DIR)/$(BINARY)"
	@echo "  lint       Roda o golangci-lint"
	@echo "  test       Roda os testes com -race"
	@echo "  bench      Roda os benchmarks e grava em $(BENCH_OUT)"
	@echo "  fuzz       Roda um alvo de fuzz (FUZZ_PKG=... FUZZ=...)"
	@echo "  stress     Roda os testes com -race -count=50"
	@echo "  cover      Gera cobertura (resumo + coverage.html)"
	@echo "  benchcmp   Compara $(OLD) e $(NEW) com benchstat"

work:
	@test -f go.work || go work init
	go work use -r .

# Os comandos rodam da raiz, que nao e um modulo: precisam do go.work.
go.work:
	$(MAKE) work

fmt:
	golangci-lint fmt $(PKGS)

build: | go.work
	go build -o $(BIN_DIR)/$(BINARY) $(CMD)

lint: | go.work
	golangci-lint run $(PKGS)

test: | go.work
	go test -race $(PKGS)

bench: | go.work
	go test -run='^$$' -bench=. -benchmem -count=$(BENCH_COUNT) $(PKGS) > $(BENCH_OUT); \
		status=$$?; cat $(BENCH_OUT); exit $$status

fuzz: | go.work
	@test -n "$(FUZZ_PKG)" -a -n "$(FUZZ)" || { echo "uso: make fuzz FUZZ_PKG=./internal/event FUZZ=FuzzParseEvent"; exit 2; }
	go test -run='^$$' -fuzz='^$(FUZZ)$$' -fuzztime=$(FUZZTIME) $(FUZZ_PKG)

stress: | go.work
	go test -race -count=50 $(PKGS)

cover: | go.work
	go test -coverprofile=coverage.out $(PKGS)
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html

benchcmp:
	benchstat $(OLD) $(NEW)