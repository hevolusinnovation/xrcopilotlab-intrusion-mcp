# The public address of the lab: Microsoft Dev Tunnels, run here so that nothing is installed on the Mac.
# devtunnel hosts a port of this container; socat forwards it to lab-01's API port. Login with a device code, from the console.
FROM ubuntu:24.04
ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 socat libicu74 \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /usr/local/bin/devtunnel "https://tunnelsassetsprod.blob.core.windows.net/cli/linux-$([ "$TARGETARCH" = "arm64" ] && echo arm64 || echo x64)-devtunnel" \
 && chmod +x /usr/local/bin/devtunnel
COPY controller.py /tunnel/
# devtunnel keeps its login in ./DevTunnels: run from /root, the tunnel-login volume, so the login survives make lab-down.
WORKDIR /root
EXPOSE 8092
CMD ["python3", "-u", "/tunnel/controller.py"]
