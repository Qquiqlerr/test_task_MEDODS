FROM golang:1.22 AS builder
LABEL authors="aleksejmetlusko"

WORKDIR /app
COPY go.mod go.sum ./
COPY config/local.yaml ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd

FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/local.yaml .
CMD ["./main"]