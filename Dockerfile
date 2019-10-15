### Build
###
FROM golang:alpine as builder

WORKDIR /go/src/github.com/youritcity/auth
COPY . .

RUN cd server && CGO_ENABLED=0 go build

###
### Run
###
FROM alpine

RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=builder /go/src/github.com/youritcity/auth/server/server auth
#COPY --from=builder /go/src/github.com/youritcity/auth/server/template template
# COPY server/config.toml .

CMD [ "./auth" ]
