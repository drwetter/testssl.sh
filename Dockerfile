# syntax=docker.io/docker/dockerfile:1

ARG LEAP_VERSION=15.4
ARG INSTALL_ROOT=/rootfs

FROM opensuse/leap:${LEAP_VERSION} as builder
ARG CACHE_ZYPPER=/tmp/cache/zypper
ARG INSTALL_ROOT
# --mount is only necessary for persisting the zypper cache on the build host,
# Paired with --cache-dir below, RUN layer invalidation does not clear this cache.
# Not useful for CI, only local builds that retain the storage.
RUN --mount=type=cache,target="${CACHE_ZYPPER}",sharing=locked <<EOF
  # Provides $VERSION_ID
  source /etc/os-release
  ZYPPER_OPTIONS=(
    --releasever "${VERSION_ID}"
    --installroot "${INSTALL_ROOT}"
    --cache-dir "${CACHE_ZYPPER}"
  )

  # Sync package repos:
  zypper ${ZYPPER_OPTIONS[@]} --gpg-auto-import-keys refresh

  zypper ${ZYPPER_OPTIONS[@]} --non-interactive install \
    --download-in-advance --no-recommends \
    bash procps grep gawk sed coreutils busybox-util-linux busybox-vi ldns libidn2-0 socat openssl curl


  ## Cleanup (reclaim approx 13 MiB):
  # None of this content should be relevant to the container:
  rm -r "${INSTALL_ROOT}/usr/share/"{licenses,man,locale,doc,help,info}
  # Functionality that the container doesn't need:
  rm "${INSTALL_ROOT}/usr/share/misc/termcap"
  rm -r "${INSTALL_ROOT}/usr/lib/sysimage/rpm"
EOF


# Create a new image with the contents of $INSTALL_ROOT
FROM scratch
ARG INSTALL_ROOT
COPY --link --from=builder ${INSTALL_ROOT} /
WORKDIR /home/testssl
RUN --mount=type=bind,from=busybox:latest,source=/bin,target=/bin <<EOF
  /bin/adduser -D -s /bin/bash testssl
  /bin/ln -s /home/testssl/testssl.sh /usr/local/bin/
EOF

# Copy over build context (after filtered by .dockerignore): bin/ etc/ testssl.sh
COPY --chown=testssl:testssl . /home/testssl/
USER testssl
ENTRYPOINT ["testssl.sh"]
CMD ["--help"]
