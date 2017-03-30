FROM debian:latest

RUN apt-get update && apt-get install -y git bsdmainutils dnsutils ldnsutils host

#ADD ./ /testssl/

RUN git clone https://github.com/drwetter/testssl.sh.git /testssl.sh/

RUN ln -s /testssl.sh/testssl.sh /usr/local/bin/

WORKDIR /testssl.sh/

ENTRYPOINT ["testssl.sh","--openssl","/testssl.sh/bin/openssl.Linux.x86_64"]
