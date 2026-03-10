# --- HELM-PATH MAKEFILE ---
# For the Vigil of Helm, the Watcher.

SHELL := /bin/bash

.PHONY: deploy vigil chronicle list-vigils clean

# Deploy and forge the application
deploy:
	@chmod +x deploy.sh
	@./deploy.sh

# Commence a new Vigil
# Usage: make vigil name=my_session
vigil:
	@helm-path start --session-name "$(name)"

# Summon the Scribe to chronicle your deeds
# Usage: make chronicle id=my_session
chronicle:
	@helm-path report "$(id)"

# List all previous vigils
list-vigils:
	@helm-path list-sessions

# Remove forged build files
clean:
	@echo "🧹  Cleansing build artifacts..."
	@rm -rf build/ dist/ *.egg-info/ src/helm_path.egg-info/
