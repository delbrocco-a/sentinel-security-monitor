FROM golang:1.24 AS builder
WORKDIR /app
COPY . .
RUN go build -o sentinel .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/sentinel .
CMD ["./sentinel"]
