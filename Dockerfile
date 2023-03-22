# syntax=docker.io/docker/dockerfile:1
# HereDoc (EOF) feature (avoids needing `&& \`) requires BuildKit:
# https://docs.docker.com/engine/reference/builder/#here-documents
ARG LEAP_VERSION=15.4
ARG CACHE_ZYPPER=/tmp/cache/zypper
ARG INSTALL_ROOT=/rootfs

FROM opensuse/leap:${LEAP_VERSION} as builder
ARG CACHE_ZYPPER
ARG INSTALL_ROOT
# --mount is only necessary for persisting the zypper cache on the build host,
# Paired with --cache-dir below, RUN layer invalidation does not clear this cache.
# Not useful for CI, only local builds that retain the storage.
RUN --mount=type=cache,target="${CACHE_ZYPPER}",sharing=locked <<EOF
  INSTALL_DEPS=()

  # Mandatory commands. coreutils required over busybox for date command:
  # https://github.com/drwetter/testssl.sh/commit/d1f03801738c87b6af39372c45e048af78c73c09
  INSTALL_DEPS+=(bash procps grep gawk sed coreutils)

  # Support better performance and debugging than hexdump via xxd:
  # https://github.com/drwetter/testssl.sh/pull/1862
  # busybox-util-linux (mandatory: hexdump) + busybox-vi (optional: xxd)
  INSTALL_DEPS+=( busybox-util-linux busybox-vi )

  # Support IDN (Internationalized Domain Names) lookups with drill:
  # https://github.com/drwetter/testssl.sh/pull/1326
  INSTALL_DEPS+=( ldns libidn2-0 )

  # Support StartTLS injection:
  # https://github.com/drwetter/testssl.sh/pull/1810
  INSTALL_DEPS+=( socat openssl )

  # Support --phone-out checks:
  # https://github.com/drwetter/testssl.sh/commit/a66f5cfdbcd93427f4408bdd8cfc336488c02bb8
  INSTALL_DEPS+=( curl )


  # Provides $VERSION_ID
  source /etc/os-release

  # --releasever required due to no version info in install root.
  # --installroot installs to location as if it was the system root.
  # --cache-dir with above `RUN --mount` speeds this step up.
  ZYPPER_OPTIONS=(
    --releasever "${VERSION_ID}"
    --installroot "${INSTALL_ROOT}"
    --cache-dir "${CACHE_ZYPPER}"
  )

  # Sync package repos to get latest updates:
  zypper ${ZYPPER_OPTIONS[@]} --gpg-auto-import-keys refresh

  zypper ${ZYPPER_OPTIONS[@]} --non-interactive install \
    --download-in-advance --no-recommends ${INSTALL_DEPS[@]}


  # Clears the cache, but this is not stored in the install root location (like DNF does), thus not useful.
  # zypper ${ZYPPER_OPTIONS[@]} clean --all

  # Unlike DNF, there isn't a `--nodocs` install option, manually remove some excess weight (9 MiB):
  rm -r "${INSTALL_ROOT}/usr/share/"{licenses,man,locale,doc,help,info}
  # Neither of these should be needed in the container, removes 4MiB
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
