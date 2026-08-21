#!/usr/bin/env bash
# Fails when the three places that name slapd's modules have drifted apart.
#
#   image/Dockerfile             what is compiled (--enable-X=mod, plus argon2,
#                                which is --enable-argon2 rather than =mod)
#   image/ldifs/01-cn-config.ldif what slapd is told to load at bootstrap
#   charts/ldapium/templates/ui-deployment.yaml
#                                what the management UI reports it has
#
# The first two disagreeing is a server that will not start: slapd refuses a
# olcModuleload for a module the image does not contain. The third disagreeing
# is quieter and worse — the UI keeps reporting an inventory that was true when
# someone typed it, which is exactly the kind of claim an audit asks about.
set -eu

cd "$(dirname "$0")/.."

fail=0
note() {
	printf '  %s\n' "$1"
	fail=1
}

# --enable-mdb builds back_mdb.la; every other --enable-X=mod builds X.la.
compiled=$(
	{
		sed -n 's/^ *--enable-\([a-z0-9]*\)=mod.*/\1/p' image/Dockerfile |
			sed 's/^mdb$/back_mdb/'
		# argon2 is a password hashing module, configured with a plain
		# --enable-argon2, but it loads exactly like the rest.
		grep -q -- '--enable-argon2' image/Dockerfile && echo argon2
	} | sort -u
)

loaded=$(sed -n 's/^olcModuleload: \([a-z0-9_]*\)\.la$/\1/p' image/ldifs/01-cn-config.ldif | sort -u)

reported=$(
	sed -n 's/^ *value: "\(back_mdb,.*\)"$/\1/p' charts/ldapium/templates/ui-deployment.yaml |
		tr ',' '\n' | sort -u
)

for name in compiled loaded reported; do
	eval "value=\$$name"
	if [ -z "$value" ]; then
		echo "could not read the $name module list; check the parsing in this script" >&2
		exit 2
	fi
done

printf 'compiled into the image: %s\n' "$(echo "$compiled" | tr '\n' ' ')"
printf 'loaded by cn=config:    %s\n' "$(echo "$loaded" | tr '\n' ' ')"
printf 'reported by the UI:     %s\n' "$(echo "$reported" | tr '\n' ' ')"

if [ "$compiled" != "$loaded" ]; then
	note "the image and cn=config disagree — slapd will not start:"
	diff <(echo "$compiled") <(echo "$loaded") | sed 's/^/    /' || true
fi

if [ "$loaded" != "$reported" ]; then
	note "cn=config and the UI's OPENLDAP_MODULES disagree:"
	diff <(echo "$loaded") <(echo "$reported") | sed 's/^/    /' || true
fi

if [ "$fail" -ne 0 ]; then
	echo "module inventory has drifted" >&2
	exit 1
fi

echo "module inventory agrees across the image, cn=config, and the UI"
