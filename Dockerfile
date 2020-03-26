FROM golang

ADD server /go/src/absCAServer/server
ADD utils /go/src/absCAServer/utils

RUN go install absCAServer/server

ENTRYPOINT [ "/go/bin/server" ]

EXPOSE 6054
