## Build
FROM golang:1.19 AS build
WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY pkgs/go.mod ./pkgs/
COPY pkgs/go.sum ./pkgs/
RUN cd pkgs && go mod download && cd ..

COPY *.go ./
COPY pkgs ./

RUN CGO_ENABLED=0 go build -o /simple-service-account .

## Deploy
FROM alpine:3

WORKDIR /srv

COPY --from=build /simple-service-account /srv/ssa
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/srv/ssa"]
