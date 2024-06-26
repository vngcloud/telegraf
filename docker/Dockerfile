FROM buildpack-deps:bullseye-curl

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iputils-ping snmp procps lm-sensors libcap2-bin && \
    rm -rf /var/lib/apt/lists/*

ARG ARG_VERSION
ENV TELEGRAF_VERSION $ARG_VERSION

ARG ARG_GITHUB_REPOSITORY
ENV GITHUB_REPOSITORY $ARG_GITHUB_REPOSITORY

RUN echo ${TELEGRAF_VERSION}

RUN ARCH= && dpkgArch="$(dpkg --print-architecture)" && \
    case "${dpkgArch##*-}" in \
      amd64) ARCH='amd64';; \
      arm64) ARCH='arm64';; \
      armhf) ARCH='armhf';; \
      armel) ARCH='armel';; \
      *)     echo "Unsupported architecture: ${dpkgArch}"; exit 1;; \
    esac && \
    wget --no-verbose https://github.com/${GITHUB_REPOSITORY}/releases/download/${TELEGRAF_VERSION}/telegraf_nightly_${ARCH}.deb && \
    dpkg -i telegraf_nightly_${ARCH}.deb && \
    rm -f telegraf_nightly_${ARCH}.deb*

EXPOSE 8125/udp 8092/udp 8094

COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["telegraf"]
