# Project

BINARY = sfn-xml-sign
SRC = xmldsign internal cmd main.go

.DEFAULT_GOAL = build


# Init

.PHONY: init

init:
	cd data && make


# Build

.PHONY: build

build:
	go build -o $(BINARY) main.go


# Format

.PHONY: fmt

fmt:
	gofmt -l -w $(SRC)


# Lint

.PHONY: lint lint-modtidy lint-gofmt

lint: lint-modtidy lint-gofmt

lint-modtidy:
	go mod tidy -diff

lint-gofmt:
	gofmt -d -e $(SRC)


# Clean

.PHONY: clean

clean:
	go clean
	rm -rf $(BINARY)
