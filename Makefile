.PHONY: help build run stop clean logs shell setup restart status

# Docker configuration
IMAGE_NAME := network-analyzer
CONTAINER_NAME := network-analyzer-app
PORT := 8080

.DEFAULT_GOAL := help

help: ## Show available commands
	@echo "🔧 AI-Assisted Network Exposure Analysis"
	@echo ""
	@echo "Quick Start:"
	@echo "  1. make setup"
	@echo "  2. Edit .env and add your ANTHROPIC_API_KEY"
	@echo "  3. make build"
	@echo "  4. make run"
	@echo "  5. Open http://localhost:8080"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup - copy .env.example and show instructions
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "✅ Created .env file"; \
		echo ""; \
		echo "⚠️  IMPORTANT: Edit .env and add your ANTHROPIC_API_KEY"; \
		echo "   Get your key from: https://console.anthropic.com/"; \
		echo ""; \
		echo "Next steps:"; \
		echo "  1. Edit .env file"; \
		echo "  2. Run: make build"; \
		echo "  3. Run: make run"; \
	else \
		echo "✅ .env file already exists"; \
	fi

build: ## Build Docker image
	@echo "🔨 Building Docker image..."
	docker build -t $(IMAGE_NAME) .
	@echo "✅ Build complete!"

run: ## Run application in Docker container
	@if [ ! -f .env ]; then \
		echo "❌ Error: .env file not found"; \
		echo "Run 'make setup' first"; \
		exit 1; \
	fi
	@echo "🚀 Starting application..."
	docker run -d \
		--name $(CONTAINER_NAME) \
		-p $(PORT):8080 \
		--env-file .env \
		-v $(PWD)/data:/app/data \
		$(IMAGE_NAME)
	@echo "✅ Application running!"
	@echo "🌐 Open: http://localhost:$(PORT)"
	@echo ""
	@echo "Useful commands:"
	@echo "  make logs  - View application logs"
	@echo "  make stop  - Stop application"

stop: ## Stop and remove container
	@echo "🛑 Stopping application..."
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@echo "✅ Stopped!"

clean: ## Stop container and remove image
	@echo "🧹 Cleaning up..."
	@make stop
	@docker rmi $(IMAGE_NAME) 2>/dev/null || true
	@echo "✅ Cleanup complete!"

logs: ## View application logs
	@docker logs -f $(CONTAINER_NAME)

shell: ## Open shell in running container
	@docker exec -it $(CONTAINER_NAME) /bin/bash

restart: stop run ## Restart application

status: ## Check if application is running
	@docker ps --filter name=$(CONTAINER_NAME) --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
