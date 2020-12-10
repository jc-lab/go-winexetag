FROM golang:1.13

ADD . /go/src/github.com/ianatha/go-winexetag

RUN go install github.com/ianatha/go-winexetag/cmd/exetag-httpd

ENTRYPOINT /go/bin/extag-httpd

EXPOSE 8080