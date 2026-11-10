// =====================================================================
// xrcopilotlab-intrusion-mcp — the demo deployment: one Container App in simulated mode on the shared MCP environment
// (hev-coi-mcp-env), image from crhevoluscoi. A real host does not use this file: the server runs on the host itself
// (deploy/linux), next to fail2ban, because it reads the host's logs.
// =====================================================================

@description('Region')
param location string = resourceGroup().location

@description('Container image full reference.')
param containerImage string

@description('Container App name.')
param appName string = 'hev-intrusion-mcp'

@description('Host name the simulated logs carry.')
param simulatedHostname string = 'bastion-01'

@description('SHA-256 hex lowercase of the API key XRCopilotLab sends in X-API-Key. The clear key stays in Key Vault.')
@secure()
param apiKeyHash string

// Scale to zero (.claude/rules/azure-scale-to-zero.md of the webapp): stateless, called only by the platform.
// The HTTP scale rule wakes it on the first request.
@description('Min replicas. 0: stateless server, answers only platform calls.')
param minReplicas int = 0
@description('Max replicas.')
param maxReplicas int = 2
@description('Concurrent requests per replica for the HTTP scale rule.')
param scaleHttpConcurrent int = 20

var acaEnvName = 'hev-coi-mcp-env'
var acrName = 'crhevoluscoi'
var appiName = 'hev-coi-mcp-appi'
var uamiName = 'hev-coi-mcp-uami'

resource acaEnv 'Microsoft.App/managedEnvironments@2024-03-01' existing = { name: acaEnvName }
resource appi 'Microsoft.Insights/components@2020-02-02' existing = { name: appiName }
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = { name: uamiName }

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${uami.id}': {} }
  }
  properties: {
    managedEnvironmentId: acaEnv.id
    configuration: {
      ingress: {
        external: true
        targetPort: 8080
        transport: 'auto'
        traffic: [ { latestRevision: true, weight: 100 } ]
        allowInsecure: false
      }
      registries: [
        { server: '${acrName}.azurecr.io', identity: uami.id }
      ]
      secrets: [
        { name: 'api-key-hash', value: apiKeyHash }
      ]
    }
    template: {
      containers: [
        {
          name: 'server'
          image: containerImage
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
            { name: 'Server__Mode', value: 'simulated' }
            { name: 'Simulation__Hostname', value: simulatedHostname }
            { name: 'ApiKeys__Hash', secretRef: 'api-key-hash' }
            { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appi.properties.ConnectionString }
          ]
          probes: [
            { type: 'Startup', httpGet: { path: '/healthz', port: 8080 }, periodSeconds: 5, failureThreshold: 24 }
            { type: 'Liveness', httpGet: { path: '/livez', port: 8080 }, periodSeconds: 30 }
            { type: 'Readiness', httpGet: { path: '/healthz', port: 8080 }, periodSeconds: 10 }
          ]
        }
      ]
      scale: {
        minReplicas: minReplicas
        maxReplicas: maxReplicas
        rules: [ { name: 'http-rule', http: { metadata: { concurrentRequests: '${scaleHttpConcurrent}' } } } ]
      }
    }
  }
}

output appName string = app.name
output appFqdn string = app.properties.configuration.ingress.fqdn
output mcpEndpoint string = 'https://${app.properties.configuration.ingress.fqdn}/mcp'
