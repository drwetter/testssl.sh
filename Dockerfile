FROM alpine:latest

WORKDIR /home/testssl/

RUN apk add --no-cache \ 
    bash \
    procps \
    drill \
    git \
    coreutils \ 
    curl

RUN addgroup testssl
RUN adduser -G testssl -g "testssl user" -s /bin/bash -D testssl

RUN ln -s testssl.sh /usr/local/bin/

USER testssl

RUN git clone --depth=1 https://github.com/drwetter/testssl.sh.git .

ENTRYPOINT ["testssl.sh"]

CMD ["--help"]
