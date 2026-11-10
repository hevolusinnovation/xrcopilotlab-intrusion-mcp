# syntax=docker/dockerfile:1.7
# xrcopilotlab-intrusion-mcp — read-only MCP server over fail2ban and sshd logs (real host or simulated host).
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY global.json Directory.Build.props Directory.Packages.props nuget.config ./
COPY src/XrCopilotLab.Intrusion.Mcp.Core/XrCopilotLab.Intrusion.Mcp.Core.csproj     src/XrCopilotLab.Intrusion.Mcp.Core/
COPY src/XrCopilotLab.Intrusion.Mcp.Server/XrCopilotLab.Intrusion.Mcp.Server.csproj src/XrCopilotLab.Intrusion.Mcp.Server/
RUN dotnet restore src/XrCopilotLab.Intrusion.Mcp.Server/XrCopilotLab.Intrusion.Mcp.Server.csproj

COPY src/ src/
RUN dotnet publish src/XrCopilotLab.Intrusion.Mcp.Server/XrCopilotLab.Intrusion.Mcp.Server.csproj \
    -c Release -o /app /p:UseAppHost=false /p:DebugType=portable

# -extra: ICU and tzdata. The logs are in the host's local time (Simulation:TimeZone, Logs:TimeZone), and country names come from ICU.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra AS runtime
WORKDIR /app
COPY --from=build /app .

# Urls (not ASPNETCORE_URLS): appsettings.json binds 127.0.0.1 for a real host behind nginx, this overrides it.
ENV Urls=http://+:8080
ENV DOTNET_RUNNING_IN_CONTAINER=true
EXPOSE 8080

USER $APP_UID
ENTRYPOINT ["dotnet", "XrCopilotLab.Intrusion.Mcp.Server.dll"]
