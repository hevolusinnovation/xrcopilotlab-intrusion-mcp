# =====================================================================
# Makefile xrcopilotlab-intrusion-mcp
#
#   make build                                 # dotnet build of the solution (Release)
#   make test                                  # unit tests
#   make run                                   # local server, simulated mode, on http://localhost:5290 (needs INTRUSION_MCP_API_KEY)
#   make docker-build TAG=1.0.0                # local image
#   make docker-push  TAG=1.0.0                # ACR push (after `az acr login -n crhevoluscoi`)
#   make deploy       TAG=1.0.0                # demo Container App hev-intrusion-mcp, simulated mode (needs INTRUSION_MCP_API_KEY)
#   make smoke                                 # /healthz on the deployed fqdn
#   make package      VERSION=1.0.0            # tarball for a real host (RID=linux-x64|linux-arm64): single binary + systemd unit + install script
#   make up                                    # = lab-up
#   make down                                  # = lab-down
#   make lab-build                             # builds the lab images (lab-01, attacker, tunnel) without starting them
#   make lab-up                                # Docker lab: Ubuntu server with the package installed + attack console on http://localhost:8090
#   make lab-down                              # stops the lab (keeps the tunnel login: same public address)
#   make lab-restart                           # lab-down + lab-up, rebuilding the images
#   make lab-rebuild                           # rebuilds the images from scratch (no cache) and restarts the lab
#   make lab-ps                                # state and health of the lab's containers
#   make lab-logs     [SVC=tunnel]             # follows the logs (all containers, or one: lab-01|attacker|tunnel)
#   make lab-shell    [SVC=lab-01]             # shell in a lab container
#   make lab-open                              # opens the console in the browser
#   make lab-reset                             # stops the lab and deletes all its state, tunnel login included
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
RID     ?= linux-x64
SVC     ?= lab-01
LAB     := docker compose -f lab/docker-compose.yml --env-file lab/.env

.PHONY: help build test run docker-build docker-push deploy smoke package key up down \
        lab-build lab-up lab-down lab-restart lab-rebuild lab-ps lab-logs lab-shell lab-open lab-reset

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
	deploy/package.sh $(VERSION) $(RID) out

# Reads the key from the terminal so it never lands in the shell history: `make key`
key:
	@read -s -p "key: " K; echo; printf '%s' "$$K" | shasum -a 256 | cut -d' ' -f1

# The lab key lives in lab/.env (git-ignored), created on the first run; the console sends it, the server keeps its hash.
lab/.env:
	@printf 'LAB_API_KEY=%s\n' "$$(openssl rand -hex 32)" > $@
	@echo "created lab/.env with a new lab key"

up: lab-up
down: lab-down

lab-build: lab/.env
	$(LAB) build

lab-up: lab/.env
	$(LAB) up -d --build
	@echo "console: http://localhost:8090"

# Keeps the Dev Tunnels login and the tunnel id (volume tunnel-login): the public address stays the same.
lab-down: lab/.env
	$(LAB) down

lab-restart: lab-down lab-up

lab-rebuild: lab/.env
	$(LAB) build --no-cache
	$(LAB) up -d --force-recreate
	@echo "console: http://localhost:8090"

lab-ps: lab/.env
	$(LAB) ps

lab-logs: lab/.env
	$(LAB) logs -f --tail=200 $(if $(filter command line,$(origin SVC)),$(SVC))

lab-shell: lab/.env
	$(LAB) exec $(SVC) bash

lab-open:
	open http://localhost:8090

# Deletes everything, the tunnel login too: the next tunnel gets a new address.
lab-reset: lab/.env
	$(LAB) down -v
