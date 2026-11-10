using './main.bicep'

param containerImage = ''
// apiKeyHash comes from the Makefile (computed from INTRUSION_MCP_API_KEY, never written here).
param apiKeyHash = ''

// Scale to zero: stateless server, called only by the platform (see main.bicep).
param minReplicas = 0
param maxReplicas = 2
param scaleHttpConcurrent = 20
