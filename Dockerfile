FROM golang

ADD server /go/src/absCAServer/server
ADD utils /go/src/absCAServer/utils

COPY server/rca.crt /go/rca.crt
COPY server/rca.key /go/rca.key

RUN go install absCAServer/server

ENTRYPOINT [ "/go/bin/server" ]

EXPOSE 6054
