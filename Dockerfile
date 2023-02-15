FROM alpine:3.17

RUN apk --no-cache --upgrade add bash procps drill git coreutils libidn curl socat openssl xxd && \
    adduser -D -s /bin/bash testssl && \
    ln -s /home/testssl/testssl.sh /usr/local/bin/ 

USER testssl
WORKDIR /home/testssl/

# Copy over build context (after filtered by .dockerignore): bin/ etc/ testssl.sh
COPY --chown=testssl:testssl . /home/testssl/

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
