build:
	@go build -o ./bin/udp-socket-manager ./main.go

test:
	go test -v ./...

run: build
	@./bin/udp-socket-manager

# Variables
PROTO_DIRS  = $(shell find . -name '*.proto' -exec dirname {} \; | sort -u) # Find unique directories containing .proto files

# Rule to generate Go code
genpb: 
	@echo "Generating Go code from .proto files..."
	@for dir in $(PROTO_DIRS); do \
		echo "Processing directory: $$dir"; \
		protoc -I $$dir --go_out=$$dir $$dir/*.proto; \
	done
	@echo "Protobuf generation complete!"

# List of tools to install
TOOLS = \
	google.golang.org/protobuf/cmd/protoc-gen-go@v1.35.2

# Rule to install tools
.PHONY: tools
tools:
	@echo "Installing tools..."
	@for tool in $(TOOLS); do \
		echo "Installing $$tool"; \
		go install $$tool; \
	done
	@echo "All tools installed!"

# Install tools 
setup--dev: tools  @go mod tidy
