FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/raksa-webshield ./cmd/raksa-webshield

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/raksa-webshield /raksa-webshield

USER nonroot:nonroot
ENTRYPOINT ["/raksa-webshield"]
CMD ["version"]
