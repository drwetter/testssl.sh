FROM alpine:3.17.1@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a

RUN apk update && \
    apk upgrade -a && \
    apk add --no-cache bash procps drill git coreutils libidn curl && \
    addgroup testssl && \
    adduser -G testssl -g "testssl user"  -s /bin/bash -D testssl && \
    ln -s /home/testssl/testssl.sh /usr/local/bin/ && \
    mkdir -m 755 -p /home/testssl/etc /home/testssl/bin

USER testssl
WORKDIR /home/testssl/

COPY --chown=testssl:testssl etc/. /home/testssl/etc/
COPY --chown=testssl:testssl bin/. /home/testssl/bin/
COPY --chown=testssl:testssl testssl.sh  /home/testssl/

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
