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
#
# Optional modules are the one deliberate asymmetry. They are compiled into the
# image but loaded only when a Helm toggle (-> LDAP_*_ENABLED) is on, so they
# are absent from the bootstrap ldif and the UI lists them conditionally.
# OPTIONAL below is the single place that declares them; the script then checks
# each is built, absent from the bootstrap ldif, really loaded by the
# entrypoint under that toggle, and that the UI conditional names exactly the
# module and toggle declared here. Everything else must match exactly.
set -eu

cd "$(dirname "$0")/.."

# name:kind:helm-toggle:entrypoint-flag
#   kind=load   slapd module added by the entrypoint with olcModuleLoad <name>.la
#   kind=check  ppolicy check module, a plain <name>.so built by the Dockerfile
#               and set via olcPPolicyCheckModule (not a slapd module)
OPTIONAL="
nestgroup:load:nestgroupEnabled:LDAP_NESTGROUP_ENABLED
ppm:check:ppmEnabled:LDAP_PPM_ENABLED
"

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

# The UI value is a base list plus Helm conditionals of exactly the shape
#   {{ if .Values.ldap.modules.<toggle> }},<name>{{ end }}
# Split them so the base can be compared as a plain list and every conditional
# piece can be checked against OPTIONAL below.
ui_line=$(sed -n 's/^ *value: "\(back_mdb,.*\)"$/\1/p' charts/ldapium/templates/ui-deployment.yaml)
cond_re='{{ if \.Values\.ldap\.modules\.[A-Za-z]* }},[a-z0-9_]*{{ end }}'
reported=$(printf '%s\n' "${ui_line%%'{{'*}" | tr ',' '\n' | sort -u)
reported_cond=$(
	printf '%s\n' "$ui_line" | grep -o "$cond_re" |
		sed 's/^{{ if \.Values\.ldap\.modules\.\([A-Za-z]*\) }},\([a-z0-9_]*\){{ end }}$/\2:\1/' | sort -u
)
leftover=$(printf '%s\n' "$ui_line" | sed "s/$cond_re//g")

for name in compiled loaded reported; do
	eval "value=\$$name"
	if [ -z "$value" ]; then
		echo "could not read the $name module list; check the parsing in this script" >&2
		exit 2
	fi
done

# Optional "load" modules are compiled but, by design, not in the bootstrap
# ldif; take them out of the compiled list so the rest must match exactly.
optional_load=$(echo "$OPTIONAL" | awk -F: 'NF && $2 == "load" {print $1}' | sort -u)
required=$(echo "$compiled" | grep -vxF -f <(echo "$optional_load") || true)

printf 'compiled into the image: %s\n' "$(echo "$compiled" | tr '\n' ' ')"
printf 'loaded by cn=config:    %s\n' "$(echo "$loaded" | tr '\n' ' ')"
printf 'reported by the UI:     %s\n' "$(echo "$reported" | tr '\n' ' ')"
printf 'optional (declared):    %s\n' "$(echo "$OPTIONAL" | awk -F: 'NF {print $1}' | tr '\n' ' ')"

if [ "$required" != "$loaded" ]; then
	note "the image (minus optional modules) and cn=config disagree — slapd will not start:"
	diff <(echo "$required") <(echo "$loaded") | sed 's/^/    /' || true
fi

if [ "$loaded" != "$reported" ]; then
	note "cn=config and the UI's always-listed OPENLDAP_MODULES disagree:"
	diff <(echo "$loaded") <(echo "$reported") | sed 's/^/    /' || true
fi

expected_cond=$(echo "$OPTIONAL" | awk -F: 'NF {print $1 ":" $3}' | sort -u)
if [ "$expected_cond" != "$reported_cond" ]; then
	note "the UI's conditional OPENLDAP_MODULES entries (name:toggle) differ from OPTIONAL:"
	diff <(echo "$expected_cond") <(echo "$reported_cond") | sed 's/^/    /' || true
fi
if [ "$leftover" != "${ui_line%%'{{'*}" ]; then
	note "OPENLDAP_MODULES has template text that is not a plain conditional ',<name>' entry"
fi

for entry in $OPTIONAL; do
	IFS=: read -r name kind toggle flag <<EOF_ENTRY
$entry
EOF_ENTRY
	case "$kind" in
	load)
		echo "$compiled" | grep -qxF "$name" ||
			note "optional module $name is not compiled into the image"
		echo "$loaded" | grep -qxF "$name" &&
			note "optional module $name is in the bootstrap ldif; it must be loaded only by the entrypoint"
		grep -E "^ *for _mod in .*[ ]${name}([ ;]|\$)" image/entrypoint.sh >/dev/null ||
			note "image/entrypoint.sh does not load optional module $name in its olcModuleLoad loop"
		grep -q "^ *$name) _mod_on=\$$flag ;;" image/entrypoint.sh ||
			note "image/entrypoint.sh does not gate $name on $flag"
		;;
	check)
		grep -q "install .*/$name\.so " image/Dockerfile ||
			note "optional module $name.so is not built and installed by image/Dockerfile"
		grep -q "/usr/lib/openldap/$name\.so" image/entrypoint.sh ||
			note "image/entrypoint.sh never references $name.so"
		grep -q "flag_on \"\$$flag\"" image/entrypoint.sh ||
			note "image/entrypoint.sh does not gate $name on $flag"
		;;
	*)
		note "OPTIONAL entry $name has unknown kind '$kind'"
		;;
	esac
	if ! grep -A1 "name: $flag\$" charts/ldapium/templates/statefulset.yaml | grep -q "ldap\.modules\.$toggle"; then
		note "charts/ldapium/templates/statefulset.yaml does not wire .Values.ldap.modules.$toggle to $flag"
	fi
done

if [ "$fail" -ne 0 ]; then
	echo "module inventory has drifted" >&2
	exit 1
fi

echo "module inventory agrees across the image, cn=config, and the UI"
