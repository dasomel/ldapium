#
# From-source OpenLDAP 2.6.14, built and owned by this project — no osixia,
# no vegardit. See image/README.md for the full env var contract and
# image/ldifs/*.ldif for the bootstrap templates.

ARG OPENLDAP_VERSION=2.6.14
# sha256 of openldap-2.6.14.tgz, pinned from a direct fetch of
# https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-2.6.14.tgz
ARG OPENLDAP_SHA256=806dcd21d366428187fba3278da773d5930f774852c9e92517f950d585f19107

FROM debian:trixie-slim AS builder
ARG OPENLDAP_VERSION
ARG OPENLDAP_SHA256
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        libsasl2-dev \
        libltdl-dev \
        groff-base \
        pkgconf \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN curl -fsSL -o openldap.tgz \
        "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
    && printf '%s  openldap.tgz\n' "${OPENLDAP_SHA256}" | sha256sum -c - \
    && tar xzf openldap.tgz \
    && rm openldap.tgz

WORKDIR /usr/src/openldap-2.6.14
# Verified configure line (2.6.14): mdb/syncprov are on by default, these
# four overlays are off-by-default and must be requested explicitly.
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
        --with-tls=openssl \
        --with-cyrus-sasl \
    && make depend \
    && make -j"$(nproc)" \
    && make install

# Verified installed layout (do not re-derive without checking a real
# `make install` — libexecdir places slapd outside the usual sbin path):
#   /usr/lib/slapd                     slapd binary (NOT /usr/sbin/slapd)
#   /usr/sbin/slap{add,cat,index,...}  admin/maintenance tools
#   /usr/bin/ldap*                     client tools
#   /usr/lib/libldap.so*, /usr/lib/liblber.so*
#   /usr/lib/openldap/*.la, *.so*      loadable modules (module path)
#   /etc/openldap/schema/*.ldif        schema (core, cosine, inetorgperson, nis, ...)
#   /etc/openldap/slapd.ldif.default   stock cn=config template (superseded by our own)

FROM debian:trixie-slim AS runtime
ENV DEBIAN_FRONTEND=noninteractive

# libssl3 does not exist on trixie (time_t64 transition) — it's libssl3t64.
# Fail the build loudly if any of these are missing rather than guessing.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3t64 \
        libsasl2-2 \
        libltdl7 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system ldap \
    && useradd --system --no-create-home --home-dir /var/lib/openldap \
        --shell /usr/sbin/nologin --gid ldap ldap

# --- OpenLDAP binaries, libraries, and modules from the builder stage ---
COPY --from=builder /usr/lib/slapd /usr/lib/slapd
COPY --from=builder /usr/lib/openldap/ /usr/lib/openldap/
COPY --from=builder /usr/lib/libldap.so* /usr/lib/liblber.so* /usr/lib/
COPY --from=builder /usr/sbin/slap* /usr/sbin/
COPY --from=builder /usr/bin/ldap* /usr/bin/
COPY --from=builder /etc/openldap/schema/ /etc/openldap/schema/
COPY --from=builder /etc/openldap/ldap.conf /etc/openldap/ldap.conf

# slapd is installed under libexecdir (/usr/lib/slapd, not /usr/sbin/slapd) —
# symlink it onto PATH so `exec slapd ...` in entrypoint.sh resolves normally.
RUN ln -s /usr/lib/slapd /usr/local/sbin/slapd \
    && ldconfig

# --- Our own bootstrap templates + entrypoint ---
COPY ldifs/01-cn-config.ldif ldifs/02-cn-config-admin.ldif ldifs/03-base-structure.ldif \
    /usr/local/share/openldap-suite/bootstrap/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

RUN mkdir -p /etc/openldap/slapd.d /var/lib/openldap/data /var/lib/openldap/run \
    && chown -R ldap:ldap /etc/openldap/slapd.d /var/lib/openldap \
    && chmod 700 /var/lib/openldap/data \
    && mkdir -p /opt/ldifs \
    && chown ldap:ldap /opt/ldifs

ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV LDAP_SEED_DIR=/opt/ldifs

USER ldap
WORKDIR /var/lib/openldap

VOLUME ["/etc/openldap/slapd.d", "/var/lib/openldap/data"]
EXPOSE 389 636

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ldapwhoami -x -H "ldapi://%2Fvar%2Flib%2Fopenldap%2Frun%2Fldapi" || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
