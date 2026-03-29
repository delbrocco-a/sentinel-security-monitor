FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o sentinel .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/sentinel .
CMD ["./sentinel"]
