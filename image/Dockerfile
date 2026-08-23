#
# From-source OpenLDAP 2.6.14, built and owned by this project — no osixia,
# no vegardit. See image/README.md for the full env var contract and
# image/ldifs/*.ldif for the bootstrap templates.

ARG OPENLDAP_VERSION=2.6.14
ARG OPENLDAP_SHA256=806dcd21d366428187fba3278da773d5930f774852c9e92517f950d585f19107

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS builder
ARG OPENLDAP_VERSION
ARG OPENLDAP_SHA256
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libsasl2-dev \
        libltdl-dev \
        libargon2-dev \
        groff-base \
        pkgconf \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
# openldap.org was the single host this whole image depended on, and retries
# alone did not save it: an outage lasting longer than the retry window takes
# out every job in the repo at once, which has now happened twice. So the
# fetch falls through to an official mirror.
#
# A second host does not weaken anything here, because the host was never what
# made the tarball trustworthy — OPENLDAP_SHA256 is, and it is checked after
# the download regardless of where the bytes came from. A mirror serving
# something else fails the build exactly as a corrupted primary would. Both
# hosts were confirmed to serve byte-identical 2.6.13 and 2.6.14 tarballs.
RUN set -eu; \
    for url in \
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
        "https://mirror.eu.oneandone.net/software/openldap/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
    ; do \
        echo "fetching ${url}"; \
        if curl -fsSL --connect-timeout 15 --retry 3 --retry-delay 5 --retry-all-errors \
                -o openldap.tgz "${url}"; then \
            break; \
        fi; \
        echo "source unreachable: ${url}" >&2; \
    done; \
    [ -s openldap.tgz ] || { echo "every OpenLDAP source was unreachable" >&2; exit 1; }; \
    printf '%s  openldap.tgz\n' "${OPENLDAP_SHA256}" | sha256sum -c -; \
    tar xzf openldap.tgz; \
    rm openldap.tgz

WORKDIR /usr/src/openldap-${OPENLDAP_VERSION}
RUN ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --libexecdir=/usr/lib \
        --enable-modules \
        --enable-mdb=mod \
        --enable-memberof=mod \
        --enable-refint=mod \
        --enable-ppolicy=mod \
        --enable-unique=mod \
        --enable-syncprov=mod \
        --enable-accesslog=mod \
        --enable-auditlog=mod \
        --enable-constraint=mod \
        --enable-deref=mod \
        --enable-dynlist=mod \
        --enable-sssvlv=mod \
        --enable-otp=mod \
        --enable-argon2 \
        --with-tls=openssl \
        --with-cyrus-sasl \
        --with-argon2=libargon2 \
    && make depend \
    && make -j"$(nproc)" \
    && make install

# Keep the exporter build isolated from the OpenLDAP source toolchain so the
# application build cache is not invalidated when exporter code changes.
# v2.9.14 declares toolchain go1.26.5, so pin the builder to that exact
# toolchain instead of relying on Go's automatic toolchain download.
#
# The upstream go.mod carries a `replace` directive, which `go install pkg@version`
# refuses outright ("the go.mod file ... contains one or more replace directives").
# So materialise the module from the checksum-verified module cache and build it
# as the main module, where replace directives are honoured.
FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS exporter-builder
ARG OPENLDAP_EXPORTER_VERSION=v2.9.14
ARG TARGETARCH
ENV CGO_ENABLED=0 GOOS=linux GOTOOLCHAIN=local
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) export GOARCH=amd64 ;; \
      arm64) export GOARCH=arm64 ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    go version; \
    go env GOOS GOARCH; \
    mod="github.com/hm-edu/openldap-exporter/v2@${OPENLDAP_EXPORTER_VERSION}"; \
    go mod download "${mod}"; \
    cp -r "$(go env GOMODCACHE)/${mod}" /src; \
    chmod -R u+w /src; \
    cd /src; \
    go build -trimpath \
        -ldflags "-s -w -X main.tag=${OPENLDAP_EXPORTER_VERSION}" \
        -o /out/openldap_exporter main.go; \
    test -x /out/openldap_exporter

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258 AS runtime
ARG OPENLDAP_VERSION

# docker/metadata-action's labels (applied at build time in build-multiarch.yml)
# document this project's own image: its version, revision, source repo. They
# say nothing about the software vendored inside it. These two do — the
# version actually compiled in this image, and where its source came from —
# so `docker inspect` answers "what OpenLDAP is this" without needing this
# Dockerfile.
LABEL io.ldapium.openldap.version="${OPENLDAP_VERSION}"       io.ldapium.openldap.source="https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz"       io.ldapium.openldap.license="OLDAP-2.8"

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3t64 \
        libsasl2-2 \
        libltdl7 \
        libargon2-1 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ldap \
    && useradd --system --no-create-home --home-dir /var/lib/openldap \
        --shell /usr/sbin/nologin --gid ldap ldap

COPY --from=builder /usr/lib/slapd /usr/lib/slapd
COPY --from=builder /usr/lib/openldap/ /usr/lib/openldap/
COPY --from=builder /usr/lib/libldap.so* /usr/lib/liblber.so* /usr/lib/
COPY --from=builder /usr/sbin/slap* /usr/sbin/
COPY --from=builder /usr/bin/ldap* /usr/bin/
COPY --from=builder /etc/openldap/schema/ /etc/openldap/schema/
COPY --from=builder /etc/openldap/ldap.conf /etc/openldap/ldap.conf
COPY --from=exporter-builder /out/openldap_exporter /usr/local/bin/openldap_exporter

# The upstream license, verbatim from the source tarball rather than retyped,
# so a copy travels with every image and not only with this repo's docs/.
COPY --from=builder /usr/src/openldap-${OPENLDAP_VERSION}/LICENSE /usr/share/doc/openldap/LICENSE

RUN ln -s /usr/lib/slapd /usr/local/sbin/slapd \
    && ldconfig

COPY ldifs/01-cn-config.ldif ldifs/02-cn-config-admin.ldif ldifs/03-base-structure.ldif \
    /usr/local/share/ldapium/bootstrap/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/openldap/slapd.d /var/lib/openldap/data /var/lib/openldap/run \
    && chown -R ldap:ldap /etc/openldap/slapd.d /var/lib/openldap \
    && chmod 700 /var/lib/openldap/data \
    && mkdir -p /opt/ldifs \
    && chown ldap:ldap /opt/ldifs

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV LDAP_SEED_DIR=/opt/ldifs
ENV LDAPTLS_REQCERT=demand
ENV LDAPTLS_CACERT=/etc/openldap/tls/ca.crt

USER 999:999
WORKDIR /var/lib/openldap

VOLUME ["/etc/openldap/slapd.d", "/var/lib/openldap/data"]
EXPOSE 389 636

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ldapwhoami -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
