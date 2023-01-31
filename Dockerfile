# syntax=docker.io/docker/dockerfile:1
FROM alpine:3.17

RUN <<EOF
  apk --no-cache --upgrade add bash procps drill git coreutils libidn curl socat openssl xxd

  # Create testssl user (and group) with no password (-D) and default shell to bash (-s):
  adduser -D -s /bin/bash testssl

  ln -s /home/testssl/testssl.sh /usr/local/bin/
  mkdir -m 755 -p /home/testssl/etc /home/testssl/bin
EOF

USER testssl
WORKDIR /home/testssl/

# Copy over build context (after filtered by .dockerignore): bin/ etc/ testssl.sh
COPY --chown=testssl . /home/testssl/

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
