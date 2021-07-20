# System setup
SHELL = bash

COVERAGE_FILE ?= coverage.txt

.PHONY: default fmt test cover goimports lint vet help clean

default:  goimports lint vet test ## Run default target : all lints + test

fmt:  ## Run go fmt to format Go files
	go fmt

test:  ## Run a basic test suite
	go test

cover:  ## Run tests and generate test coverage file, output coverage results and HTML coverage file.
	go test -coverprofile $(COVERAGE_FILE)
	go tool cover -func=$(COVERAGE_FILE)
	go tool cover -html=$(COVERAGE_FILE)
	rm -f $(COVERAGE_FILE)

goimports:  ## Run goimports to format code
	goimports -w .

lint:  ## Lint all go code in project
	golint ./...

vet:  ## Go vet all project code
	go vet ./...

help:  ## Show This Help
	@for line in $$(cat Makefile | grep "##" | grep -v "grep" | sed  "s/:.*##/:/g" | sed "s/\ /!/g"); do verb=$$(echo $$line | cut -d ":" -f 1); desc=$$(echo $$line | cut -d ":" -f 2 | sed "s/!/\ /g"); printf "%-30s--%s\n" "$$verb" "$$desc"; done

clean:  ## Clean up transient (generated) files
	go clean
	rm -f $(COVERAGE_FILE)
