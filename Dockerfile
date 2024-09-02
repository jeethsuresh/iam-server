# Stage 1: Build
FROM golang:alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Go Modules manifests
COPY go.mod go.sum ./

# Download and cache dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -o main .

# Stage 2: Run
FROM scratch

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main /main
COPY --from=builder /app/templates/ /templates/

# Command to run the executable
ENTRYPOINT ["/main"]
