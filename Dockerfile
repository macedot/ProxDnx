# ProxDnx container image: stdlib-only static binary, distroless runtime
# (CA certs included so https:// monitor URLs work). Intended for
# docker-compose deployments driven entirely by PROXDNX_* environment
# variables — see README "Docker / compose".
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/proxdnx .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/proxdnx /proxdnx
# caddy/avahi management is a host feature: containers run with
# PROXDNX_CADDY=false PROXDNX_AVAHI=false and serve the API/portal only.
EXPOSE 9973
ENTRYPOINT ["/proxdnx"]
