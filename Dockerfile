# syntax=docker.io/docker/dockerfile:1

ARG LEAP_VERSION=15.6
ARG INSTALL_ROOT=/rootfs

FROM opensuse/leap:${LEAP_VERSION} as builder
ARG CACHE_ZYPPER=/tmp/cache/zypper
ARG INSTALL_ROOT


# /etc/os-release provides $VERSION_ID below.
# We don't need the openh264.repo and the non-oss repos, just costs build time (repo caches).
# Also we need to remove the util_linux RPM to /really/ make sure busybox-util-linux gets installed.
# And we need to run zypper update, see all PR #2424.
RUN source /etc/os-release \
  && rm -f /etc/zypp/repos.d/repo-openh264.repo /etc/zypp/repos.d/repo-non-oss.repo \
  && export ZYPPER_OPTIONS=( --releasever "${VERSION_ID}" --installroot "${INSTALL_ROOT}" --cache-dir "${CACHE_ZYPPER}" ) \
  && zypper "${ZYPPER_OPTIONS[@]}" --gpg-auto-import-keys refresh \
  && rpm -e util-linux --nodeps \
  && zypper "${ZYPPER_OPTIONS[@]}" --non-interactive install --download-in-advance --no-recommends \
       bash procps grep gawk sed coreutils busybox ldns libidn2-0 socat openssl curl \
  && zypper up -y \
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
# Link busybox to tar, see #2403. Create user + (home with SGID set):
RUN  ln -s /usr/bin/busybox /usr/bin/tar \
  && ln -s /usr/bin/busybox /usr/bin/hexdump \
  && echo 'testssl:x:1000:1000::/home/testssl:/bin/bash' >> /etc/passwd \
  && echo 'testssl:x:1000:' >> /etc/group \
  && echo 'testssl:!::0:::::' >> /etc/shadow \
  && install --mode 2755 --owner testssl --group testssl --directory /home/testssl \
  && ln -s /home/testssl/testssl.sh /usr/local/bin/

# Copy over build context (after filtered by .dockerignore): bin/ etc/ testssl.sh
COPY --chown=testssl:testssl . /home/testssl/
USER testssl
ENTRYPOINT ["testssl.sh"]
CMD ["--help"]
