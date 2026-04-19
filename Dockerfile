FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o RealiTLScanner .

FROM alpine:latest
# ca-certificates needed for TLS verification, tzdata for correct timestamps
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /src/RealiTLScanner .
# Run as non-root user for better security
RUN adduser -D -u 1000 scanner && chown scanner:scanner /app/RealiTLScanner
USER scanner
ENTRYPOINT ["./RealiTLScanner"]
CMD ["--thread", "500"]
