FROM golang:alpine as builder
WORKDIR /appbuild
COPY src .
RUN go build

FROM alpine
WORKDIR /app
COPY --from=builder /appbuild/peptest .
ENTRYPOINT [ "/app/peptest" ]
CMD []
