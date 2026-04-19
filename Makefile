.PHONY: help build run stop stop-app clean clean-venv clean-all logs shell setup restart status env

# Configuration
IMAGE_NAME := network-analyzer
CONTAINER_NAME := network-analyzer-app
PORT := 8080
VENV := venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip3

.DEFAULT_GOAL := help

help: ## Show available commands
	@echo "AI-Assisted Network Exposure Analysis"
	@echo ""
	@echo "Quick Start (4 Steps):"
	@echo "  1. make setup      - Create .env file"
	@echo "  2. make env        - Edit .env and add your ANTHROPIC_API_KEY"
	@echo "  3. make build      - Create venv and install dependencies"
	@echo "  4. make run        - Start application"
	@echo ""
	@echo "Then open: http://localhost:8080"
	@echo ""
	@echo "Cleanup:"
	@echo "  make stop-app      - Stop running Flask application"
	@echo "  make clean-venv    - Remove virtual environment only"
	@echo "  make clean-all     - Stop app and remove everything"
	@echo ""
	@echo "Docker Alternative:"
	@echo "  Use 'make docker-build' and 'make docker-run' instead"
	@echo ""
	@echo "Commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Initial setup - copy .env.example and show instructions
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "[OK] Created .env file"; \
		echo ""; \
		echo "Next steps:"; \
		echo "  1. Run: make env (to edit API key)"; \
		echo "  2. Run: make build"; \
		echo "  3. Run: make run"; \
	else \
		echo "[OK] .env file already exists"; \
	fi

env: ## Edit .env file to add API keys
	@if [ ! -f .env ]; then \
		echo "[ERROR] .env file not found"; \
		echo "Run 'make setup' first"; \
		exit 1; \
	fi
	@echo "Opening .env file for editing..."
	@echo "Add your ANTHROPIC_API_KEY from: https://console.anthropic.com/"
	@open -e .env || nano .env

build: ## Create virtual environment and install dependencies
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv $(VENV); \
		echo "[OK] Virtual environment created"; \
	fi
	@echo "Installing dependencies in virtual environment..."
	@$(VENV)/bin/pip3 install --upgrade pip
	@$(VENV)/bin/pip3 install -r requirements.txt
	@echo "[OK] Dependencies installed in isolated environment!"
	@echo "[INFO] Virtual environment: $(VENV)/"
	@echo "[INFO] Verify installation: $(VENV)/bin/python3 -m pip list"

run: ## Run application with Python
	@if [ ! -d "$(VENV)" ]; then \
		echo "[ERROR] Virtual environment not found"; \
		echo "Run 'make build' first"; \
		exit 1; \
	fi
	@if [ ! -f .env ]; then \
		echo "[ERROR] .env file not found"; \
		echo "Run 'make setup' first"; \
		exit 1; \
	fi
	@echo "Starting application..."
	@echo "[OK] Application running on http://localhost:8080"
	@echo "Press Ctrl+C to stop"
	@$(VENV)/bin/python3 app.py

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME) .
	@echo "[OK] Build complete!"

docker-run: ## Run application in Docker container
	@if [ ! -f .env ]; then \
		echo "[ERROR] .env file not found"; \
		echo "Run 'make setup' first"; \
		exit 1; \
	fi
	@echo "Starting application..."
	docker run -d \
		--name $(CONTAINER_NAME) \
		-p $(PORT):8080 \
		--env-file .env \
		-v $(PWD)/data:/app/data \
		$(IMAGE_NAME)
	@echo "[OK] Application running!"
	@echo "Open: http://localhost:$(PORT)"
	@echo ""
	@echo "Useful commands:"
	@echo "  make logs  - View application logs"
	@echo "  make stop  - Stop application"

stop: ## Stop and remove container
	@echo "Stopping application..."
	@docker stop $(CONTAINER_NAME) 2>/dev/null || true
	@docker rm $(CONTAINER_NAME) 2>/dev/null || true
	@echo "[OK] Stopped!"

clean: ## Stop Docker container and remove image
	@echo "Cleaning up Docker..."
	@make stop
	@docker rmi $(IMAGE_NAME) 2>/dev/null || true
	@echo "[OK] Docker cleanup complete!"

stop-app: ## Stop running Flask application
	@echo "Stopping Flask application on port 8080..."
	@lsof -ti:8080 | xargs kill -9 2>/dev/null && echo "[OK] Application stopped!" || echo "[INFO] No application running on port 8080"

clean-venv: ## Remove virtual environment only
	@echo "Removing virtual environment..."
	@rm -rf $(VENV)
	@echo "[OK] Virtual environment removed!"
	@echo "[INFO] Run 'make build' to recreate"

clean-all: ## Remove everything (venv, data, uploads, cache) and stop app
	@echo "WARNING: This will:"
	@echo "  - Stop any running Flask application"
	@echo "  - Remove virtual environment ($(VENV)/)"
	@echo "  - Remove uploaded files (data/uploads/)"
	@echo "  - Remove Python cache (__pycache__/)"
	@echo "  - Remove .env file"
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		echo "Stopping Flask application..."; \
		lsof -ti:8080 | xargs kill -9 2>/dev/null || true; \
		echo "Removing virtual environment..."; \
		rm -rf $(VENV); \
		echo "Removing data files..."; \
		rm -rf data/uploads/*; \
		echo "Removing Python cache..."; \
		find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true; \
		find . -type f -name "*.pyc" -delete 2>/dev/null || true; \
		echo "Removing .env file..."; \
		rm -f .env; \
		echo "[OK] Complete cleanup finished!"; \
		echo "[INFO] All processes stopped, all files removed"; \
		echo "[INFO] Run 'make setup' to start fresh"; \
	else \
		echo "Cleanup cancelled"; \
	fi

logs: ## View application logs
	@docker logs -f $(CONTAINER_NAME)

shell: ## Open shell in running container
	@docker exec -it $(CONTAINER_NAME) /bin/bash

restart: stop run ## Restart application

status: ## Check if application is running
	@docker ps --filter name=$(CONTAINER_NAME) --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
