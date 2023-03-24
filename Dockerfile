# syntax=docker.io/docker/dockerfile:1

ARG LEAP_VERSION=15.4
ARG INSTALL_ROOT=/rootfs

FROM opensuse/leap:${LEAP_VERSION} as builder
ARG CACHE_ZYPPER=/tmp/cache/zypper
ARG INSTALL_ROOT
# /etc/os-release provides $VERSION_ID
RUN source /etc/os-release \
  && export ZYPPER_OPTIONS=( --releasever "${VERSION_ID}" --installroot "${INSTALL_ROOT}" --cache-dir "${CACHE_ZYPPER}" ) \
  && zypper "${ZYPPER_OPTIONS[@]}" --gpg-auto-import-keys refresh \
  && zypper "${ZYPPER_OPTIONS[@]}" --non-interactive install --download-in-advance --no-recommends \
       bash procps grep gawk sed coreutils busybox-util-linux busybox-vi ldns libidn2-0 socat openssl curl \
  && zypper "${ZYPPER_OPTIONS[@]}" clean --all
## Cleanup (reclaim approx 13 MiB):
# None of this content should be relevant to the container:
RUN  rm -r "${INSTALL_ROOT}/usr/share/"{licenses,man,locale,doc,help,info}
# Functionality that the container doesn't need:
RUN  rm    "${INSTALL_ROOT}/usr/share/misc/termcap" \
  && rm -r "${INSTALL_ROOT}/usr/lib/sysimage/rpm"


# Create a new image with the contents of $INSTALL_ROOT
FROM scratch
ARG INSTALL_ROOT
COPY --link --from=builder ${INSTALL_ROOT} /
# Create user + (home with SGID set):
RUN  echo 'testssl:x:1000:1000::/home/testssl:/bin/bash' >> /etc/passwd \
  && echo 'testssl:x:1000:' >> /etc/group \
  && echo 'testssl:!::0:::::' >> /etc/shadow \
  && install --mode 2755 --owner testssl --group testssl --directory /home/testssl \
  && ln -s /home/testssl/testssl.sh /usr/local/bin/

# Copy over build context (after filtered by .dockerignore): bin/ etc/ testssl.sh
COPY --chown=testssl:testssl . /home/testssl/
USER testssl
ENTRYPOINT ["testssl.sh"]
CMD ["--help"]
