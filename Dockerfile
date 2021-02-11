FROM alpine:3.13

RUN apk add --no-cache bash procps drill git coreutils libidn curl socat openssl && \
    adduser -s /bin/bash -D testssl && \
    ln -s /home/testssl/testssl.sh /usr/local/bin/

USER testssl
WORKDIR /home/testssl/

COPY --chown=testssl:testssl etc/. /home/testssl/etc/
COPY --chown=testssl:testssl bin/. /home/testssl/bin/
COPY --chown=testssl:testssl testssl.sh  /home/testssl/

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
