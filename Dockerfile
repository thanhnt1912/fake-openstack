FROM golang:1.25.5-alpine AS build
WORKDIR /app

# Allow Go to download newer toolchain if needed
ENV GOTOOLCHAIN=auto

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fake-openstack ./cmd/fake-openstack

FROM gcr.io/distroless/static-debian12
WORKDIR /app

# Copy the binary
COPY --from=build /app/fake-openstack /usr/local/bin/fake-openstack

# Copy OpenAPI spec
COPY openapi.yaml /app/openapi.yaml

EXPOSE 5000

ENTRYPOINT ["/usr/local/bin/fake-openstack"]
