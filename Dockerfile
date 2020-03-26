FROM golang

ADD server /go/src/absCAServer/server
ADD utils /go/src/absCAServer/utils

ADD server/rca.crt /go/
ADD server/rca.key /go/

RUN go install absCAServer/server

ENTRYPOINT [ "/go/bin/server" ]

EXPOSE 6050
