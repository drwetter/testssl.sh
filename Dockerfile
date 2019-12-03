FROM alpine:3.10

RUN apk add --no-cache curl bash procps drill git coreutils libidn

RUN addgroup testssl
RUN adduser -G testssl -g "testssl user"  -s /bin/bash -D testssl

RUN ln -s /home/testssl/testssl.sh /usr/local/bin/

USER testssl
WORKDIR /home/testssl/

RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git .

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
