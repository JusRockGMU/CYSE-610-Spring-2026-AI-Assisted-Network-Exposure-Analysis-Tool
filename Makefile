.PHONY: setup clean archive test run batch demo reset help

VENV = venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

help:
	@echo "AI-Assisted Network Exposure Analysis - Makefile Commands"
	@echo "==========================================================="
	@echo "make setup    - Create virtual environment and install dependencies"
	@echo "make clean    - Remove generated data and reset to fresh state"
	@echo "make archive  - Move old versions to archive folder"
	@echo "make test     - Run test suite"
	@echo "make run      - Execute pipeline on single scan (requires INPUT=path/to/scan.xml)"
	@echo "                Example: make run INPUT=data/raw/infosecwarrior_fileserver.xml ARGS='--baseline data/baseline/infosecwarrior_fileserver.json --evaluate'"
	@echo "make batch    - Execute pipeline on all scans in a directory (requires DIR=path/to/directory)"
	@echo "                Example: make batch DIR=datasets/vulnerable-box-resources/Infosecwarrior"
	@echo "make demo     - Run demo with synthetic sample data"
	@echo "make reset    - Complete fresh start (clean + setup)"
	@echo "make help     - Show this help message"

setup:
	@echo "Setting up project environment..."
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "Creating data directory structure..."
	@mkdir -p data/raw data/processed data/baseline data/reports archive
	@touch data/raw/.gitkeep data/processed/.gitkeep data/reports/.gitkeep
	@echo ""
	@echo "Setup complete! Next steps:"
	@echo "1. Copy .env.example to .env and add your ANTHROPIC_API_KEY (optional)"
	@echo "2. Run 'make demo' to test with synthetic data"
	@echo "3. Run 'make run INPUT=data/raw/infosecwarrior_fileserver.xml ARGS=\"--baseline data/baseline/infosecwarrior_fileserver.json --evaluate\"' for real data"

clean:
	@echo "Cleaning generated data..."
	rm -rf data/processed/*
	rm -rf data/reports/*
	@touch data/processed/.gitkeep data/reports/.gitkeep
	@echo "Clean complete!"

archive:
	@echo "Archiving old versions..."
	@mkdir -p archive/$$(date +%Y%m%d_%H%M%S)
	@if [ -n "$$(ls -A data/reports 2>/dev/null | grep -v .gitkeep)" ]; then \
		mv data/reports/* archive/$$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true; \
	fi
	@echo "Archive complete!"

test:
	@echo "Running tests..."
	$(PYTHON) -m pytest tests/ -v

run:
	@if [ -z "$(INPUT)" ]; then \
		echo "Error: INPUT parameter required. Usage: make run INPUT=data/raw/scan.xml"; \
		exit 1; \
	fi
	@echo "Running pipeline on $(INPUT)..."
	$(PYTHON) main.py --input $(INPUT) $(ARGS)

batch:
	@if [ -z "$(DIR)" ]; then \
		echo "Error: DIR parameter required. Usage: make batch DIR=path/to/directory"; \
		exit 1; \
	fi
	@if [ ! -d "$(DIR)" ]; then \
		echo "Error: Directory not found: $(DIR)"; \
		exit 1; \
	fi
	@echo "Running batch processing with summary report generation..."
	$(PYTHON) batch_process.py "$(DIR)" $(ARGS)

demo:
	@echo "Running demo with synthetic sample data..."
	@echo "(For real dataset, use: make run INPUT=data/raw/infosecwarrior_fileserver.xml ARGS='--baseline data/baseline/infosecwarrior_fileserver.json --evaluate')"
	@echo ""
	$(PYTHON) main.py --demo

reset: clean
	@echo "Performing complete reset..."
	rm -rf $(VENV)
	@echo "Reset complete! Run 'make setup' to reinitialize."

install-deps:
	$(PIP) install -r requirements.txt
