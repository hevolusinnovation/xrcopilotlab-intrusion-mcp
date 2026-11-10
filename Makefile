# =====================================================================
# Makefile xrcopilotlab-intrusion-mcp
#
#   make test                                  # unit tests
#   make run                                   # local server, simulated mode, on http://localhost:5290 (needs INTRUSION_MCP_API_KEY)
#   make docker-build TAG=1.0.0                # local image
#   make docker-push  TAG=1.0.0                # ACR push (after `az acr login -n crhevoluscoi`)
#   make deploy       TAG=1.0.0                # demo Container App hev-intrusion-mcp, simulated mode (needs INTRUSION_MCP_API_KEY)
#   make smoke                                 # /healthz on the deployed fqdn
#   make package      VERSION=1.0.0            # linux-x64 tarball for a real host: single binary + systemd unit + install script
#   make key                                   # prints the SHA-256 of a key read from the terminal (never the key)
#
# INTRUSION_MCP_API_KEY is read from the environment (e.g. from Key Vault), never written in a file of the repo.
# =====================================================================

.DEFAULT_GOAL := help

TAG     ?= dev
VERSION ?= 0.1.0
RG      ?= rg-xrcopilotlab-ai
ACR     ?= crhevoluscoi.azurecr.io
APP     ?= hev-intrusion-mcp
IMAGE   := $(ACR)/xrcopilotlab-intrusion-mcp:$(TAG)
SERVER  := src/XrCopilotLab.Intrusion.Mcp.Server/XrCopilotLab.Intrusion.Mcp.Server.csproj
DIST    := out/xrcopilotlab-intrusion-mcp-$(VERSION)-linux-x64

.PHONY: help build test run docker-build docker-push deploy smoke package key

help:
	@grep -E '^#   make' Makefile | sed 's/^#   //'

build:
	dotnet build XrCopilotLab.Intrusion.Mcp.slnx -c Release

test:
	dotnet test XrCopilotLab.Intrusion.Mcp.slnx -c Release --verbosity minimal

run:
	@test -n "$$INTRUSION_MCP_API_KEY" || (echo "INTRUSION_MCP_API_KEY is not set" && exit 1)
	Server__Mode=simulated Urls=http://localhost:5290 \
	ApiKeys__Hash=$$(printf '%s' "$$INTRUSION_MCP_API_KEY" | shasum -a 256 | cut -d' ' -f1) \
	dotnet run -c Release --project $(SERVER)

docker-build:
	docker build --platform linux/amd64 -t $(IMAGE) .

docker-push: docker-build
	docker push $(IMAGE)

deploy:
	@test -n "$$INTRUSION_MCP_API_KEY" || (echo "INTRUSION_MCP_API_KEY is not set" && exit 1)
	az deployment group create --resource-group $(RG) \
	  --template-file infra/main.bicep --parameters infra/parameters.bicepparam \
	  --parameters containerImage=$(IMAGE) appName=$(APP) \
	    apiKeyHash=$$(printf '%s' "$$INTRUSION_MCP_API_KEY" | shasum -a 256 | cut -d' ' -f1) \
	  --query 'properties.outputs' -o json

smoke:
	@FQDN=$$(az containerapp show -n $(APP) -g $(RG) --query properties.configuration.ingress.fqdn -o tsv); \
	curl -fsS https://$$FQDN/healthz && echo

package:
	rm -rf $(DIST) && mkdir -p $(DIST)
	dotnet publish $(SERVER) -c Release -r linux-x64 --self-contained true \
	  -p:PublishSingleFile=true -p:DebugType=none -o $(DIST)/bin
	cp deploy/linux/xrcopilotlab-intrusion-mcp.service deploy/linux/install.sh deploy/linux/appsettings.Production.json $(DIST)/
	chmod +x $(DIST)/install.sh
	tar -C out -czf $(DIST).tar.gz $(notdir $(DIST))
	@echo "package: $(DIST).tar.gz"

# Reads the key from the terminal so it never lands in the shell history: `make key`
key:
	@read -s -p "key: " K; echo; printf '%s' "$$K" | shasum -a 256 | cut -d' ' -f1
