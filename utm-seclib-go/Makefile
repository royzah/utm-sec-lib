# Makefile for generating test coverage data and HTML report

# The default target when you just run `make` without specifying a target.
# You can change this to whatever you want.
default: test

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  lint				Run the linter"
	@echo "  show-coverage			Show function-by-function coverage data (May require local flight blender)"
	@echo "  show-coverage-html		Open the HTML coverage report in a web browser (May require local flight blender)"
	@echo "  test				Run the tests"
	@echo "  test-pki			Run PKI-related tests"
	@echo "  clean				Remove generated files"
	@echo "  help				Show this help message"
	@echo ""

# Define the target to generate test coverage data
generate-test-data:
	@echo "Generating test coverage data..."
	@go test -short -coverprofile=coverage.out ./pkg/...

show-coverage: generate-test-data
	@echo "Showing coverage data..."
	@go tool cover -func=coverage.out

# Define the target to generate an HTML coverage report
show-coverage-html: generate-test-data
	@echo "Generating HTML coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@open coverage.html

lint:
	@echo "Running linter..."
	@golangci-lint run ./...

open-coverage: coverage
	@echo "Opening coverage data..."
	@open coverage.html

generate-test-certs:
	@echo "Generating test certificates..."
	@go run ./setup/environment-setup.go

test: generate-test-certs
	@echo "Running tests..."
	@go test -short ./...

test-pki: generate-test-certs
	@echo "Running PKI tests..."
	@go test -v -short ./pkg/ussp-pki/...

clean:
	@rm -rf coverage.html coverage.out

.PHONY: help generate-test-data coverage open-coverage test
