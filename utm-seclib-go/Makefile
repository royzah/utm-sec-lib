# Makefile for generating test coverage data and HTML report

# The default target when you just run `make` without specifying a target.
# You can change this to whatever you want.
default: test

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  lint				Run the linter"
	@echo ""

lint:
	@echo "Running linter..."
	@golangci-lint run ./...
