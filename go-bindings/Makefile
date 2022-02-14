SRC_DIR=$(PWD)/../src
BUILD_DIR=$(PWD)/../build
CACHE_DIR=$(PWD)/cache

CGO_LDFLAGS="-L$(CACHE_DIR)/lib -lbls -lrelic_s -lgmp"
CGO_CXXFLAGS="-I$(CACHE_DIR)"

GO="go"
COVERAGE_OUTPUT ?= coverage.out

.PHONY: default vet test clean

default: prepare vet test clean

prepare:
ifeq ("$(wildcard $(CACHE_DIR))", "")
	@mkdir -p $(CACHE_DIR)/chiabls $(CACHE_DIR)/lib
	@cp -r $(BUILD_DIR)/_deps/relic-src/include/* $(CACHE_DIR)
	@cp -r $(BUILD_DIR)/_deps/relic-build/include/* $(CACHE_DIR)
	@cp -r $(SRC_DIR)/* $(CACHE_DIR)/chiabls
	@find $(BUILD_DIR) -name "lib*.a" | xargs -I{} cp {} $(CACHE_DIR)/lib
endif

fmt:  ## Run go fmt to format Go files
	$(GO) fmt

test:  ## Run a basic test suite
	CGO_CXXFLAGS=$(CGO_CXXFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) $(GO) test

cover:  ## Run tests and generate test coverage file, output coverage results and HTML coverage file.
	CGO_CXXFLAGS=$(CGO_CXXFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) $(GO) test -coverprofile $(COVERAGE_OUTPUT)
	CGO_CXXFLAGS=$(CGO_CXXFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) $(GO) tool cover -func=$(COVERAGE_OUTPUT)
	CGO_CXXFLAGS=$(CGO_CXXFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) $(GO) tool cover -html=$(COVERAGE_OUTPUT)
	rm -f $(COVERAGE_OUTPUT)

vet:  ## Go vet all project code
	CGO_CXXFLAGS=$(CGO_CXXFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS) go vet ./...

help:  ## Show This Help
	@for line in $$(cat Makefile | grep "##" | grep -v "grep" | sed  "s/:.*##/:/g" | sed "s/\ /!/g"); do verb=$$(echo $$line | cut -d ":" -f 1); desc=$$(echo $$line | cut -d ":" -f 2 | sed "s/!/\ /g"); printf "%-30s--%s\n" "$$verb" "$$desc"; done

clean: ## Clean up transient (generated) files
	$(GO) clean
	rm -f $(COVERAGE_OUTPUT)
	rm -rf $(CACHE_DIR)
