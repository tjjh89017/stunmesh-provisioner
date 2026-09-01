#!/bin/sh
# test_init.sh -- tests for contrib/openwrt/stunmesh-agent.init.
#
# stunmesh-agent.init's only real logic (besides handing a command
# line to procd) is write_config: read UCI, render config.yaml, write
# it atomically at mode 0600. This file loads write_config (and the
# yaml_quote/yaml_scalar/write_plugin_entry helpers it calls) by
# sourcing a filtered copy of the real, unmodified script with only
# the ". /lib/functions.sh" line replaced by a minimal fake UCI shell
# library -- OpenWrt's real config_load/config_get do not exist off an
# OpenWrt device. The fake understands a deliberately simplified
# "[section]" / "option"/"list" fixture format, not real UCI syntax;
# see write_fake_uci_lib below. It proves write_config reads the right
# option names and renders the right YAML shape, not that OpenWrt's
# real config_load/config_get parse UCI this way.
#
# Every rendered config.yaml is parsed back with Python's PyYAML (a
# real YAML parser, not a string match) and its values checked, so an
# escaping mistake in yaml_quote (an unescaped '"' or '\' from an
# operator-chosen namespace/node_id/proxy value) would surface as a
# parse error or a wrong value here, not just as plausible-looking
# text.
#
# start_service/reload_service dispatch is checked separately with a
# minimal fake procd_* function set (procd itself does not exist off
# an OpenWrt device either): it proves start_service skips procd
# entirely when the config is incomplete, and calls
# procd_set_param command with the expected argument list otherwise.

set -u

SELF_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_SCRIPT="$SELF_DIR/../stunmesh-agent.init"

. "$SELF_DIR/lib.sh"

WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/stunmesh-init-test.XXXXXX") || exit 1
trap 'rm -rf "$WORKDIR"' EXIT

PYTHON=${PYTHON:-python3}
have_python=0
if command -v "$PYTHON" >/dev/null 2>&1 && "$PYTHON" -c 'import yaml' >/dev/null 2>&1; then
	have_python=1
fi

INTERP="${TEST_HOTPLUG_INTERP:-sh}"

scratch() {
	d="$WORKDIR/d$TESTS_RUN"
	mkdir -p "$d"
	echo "$d"
}

# write_fake_uci_lib writes a fake /lib/functions.sh into $1: a
# config_load that just remembers $UCI_CONFIG_FILE is present, and a
# config_get that reads "[section]" blocks of "option"/"list" lines
# from it. This is not real UCI syntax; see this file's header.
write_fake_uci_lib() {
	d="$1"
	cat > "$d/functions.sh" <<'EOF'
config_load() {
	[ -n "${UCI_CONFIG_FILE:-}" ] && [ -f "$UCI_CONFIG_FILE" ]
}
config_get() {
	varname="$1"
	section="$2"
	optname="$3"
	def="${4:-}"
	val=$(awk -v sect="[$section]" -v opt="$optname" '
		$0 == sect { insect=1; next }
		/^\[/ { insect=0 }
		insect && ($1=="option" || $1=="list") && $2==opt {
			$1=""; $2=""
			sub(/^  /, "")
			print
			found=1
		}
		END { if (!found) exit 1 }
	' "$UCI_CONFIG_FILE" | tr "\n" "\t")
	if [ -z "$val" ]; then
		val="$def"
	else
		val=$(printf '%s' "$val" | tr "\t" " " | sed 's/ *$//')
	fi
	eval "$varname=\"\$val\""
}
EOF
}

# write_filtered writes a copy of stunmesh-agent.init with
# ". /lib/functions.sh" pointed at the fake lib in d, and CONFIG_DIR
# pointed inside d, and returns its path.
write_filtered() {
	d="$1"
	out="$d/init-filtered"
	sed \
		-e "s#^\. /lib/functions\.sh\$#. $d/functions.sh#" \
		-e "s#^CONFIG_DIR=\"/etc/stunmesh/agent\"\$#CONFIG_DIR=\"$d/agent\"#" \
		"$INIT_SCRIPT" > "$out"
	echo "$out"
}

# yaml_get prints the value of a top-level (or "plugins.<name>.<key>")
# key from $1's YAML content, using PyYAML, or the literal string
# "PYTHON-UNAVAILABLE" if PyYAML could not be imported (skip, not
# fail, on a runner without it -- see test_writes_minimal_config's use
# of $have_python).
yaml_get() {
	file="$1"
	shift
	"$PYTHON" - "$file" "$@" <<'EOF'
import sys, yaml
with open(sys.argv[1]) as f:
    doc = yaml.safe_load(f)
node = doc
for key in sys.argv[2:]:
    if isinstance(node, list):
        node = node[int(key)]
    else:
        node = node[key]
print(node)
EOF
}

test_writes_minimal_config() {
	[ "$have_python" -eq 1 ] || return 0
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'EOF'
[main]
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
EOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; write_config" 2>"$d/stderr"
	rc=$?
	assert_eq "$rc" "0" "write_config exit code (minimal)" || return 1

	cfg="$d/agent/config.yaml"
	[ -f "$cfg" ] || { echo "  config.yaml was not written" >&2; return 1; }

	assert_eq "$(yaml_get "$cfg" namespace)" "mymesh" "namespace" || return 1
	assert_eq "$(yaml_get "$cfg" node_id)" "alpha" "node_id" || return 1
	assert_eq "$(yaml_get "$cfg" controller_pubkey)" "pk123" "controller_pubkey" || return 1

	mode=$(stat -c '%a' "$cfg" 2>/dev/null || stat -f '%Lp' "$cfg" 2>/dev/null)
	assert_eq "$mode" "600" "config.yaml mode"
}

test_writes_optional_scalars() {
	[ "$have_python" -eq 1 ] || return 0
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'EOF'
[main]
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
option refresh_interval 5m
option full_apply_interval 24h
option identity_key /custom/identity.key
option last /custom/last.json
option lock /custom/agent.lock
EOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; write_config" 2>"$d/stderr"
	rc=$?
	assert_eq "$rc" "0" "write_config exit code (optional scalars)" || return 1

	cfg="$d/agent/config.yaml"
	assert_eq "$(yaml_get "$cfg" refresh_interval)" "5m" "refresh_interval" || return 1
	assert_eq "$(yaml_get "$cfg" full_apply_interval)" "24h" "full_apply_interval" || return 1
	assert_eq "$(yaml_get "$cfg" identity_key)" "/custom/identity.key" "identity_key" || return 1
	assert_eq "$(yaml_get "$cfg" last)" "/custom/last.json" "last" || return 1
	assert_eq "$(yaml_get "$cfg" lock)" "/custom/agent.lock" "lock"
}

test_writes_use_plugin_and_plugins() {
	[ "$have_python" -eq 1 ] || return 0
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'EOF'
[main]
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
option use_plugin mydht

[mydht]
option type dhtproxy
list proxies https://dhtproxy2.jami.net
list proxies https://dhtproxy3.jami.net
EOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; write_config" 2>"$d/stderr"
	rc=$?
	assert_eq "$rc" "0" "write_config exit code (use_plugin)" || return 1

	cfg="$d/agent/config.yaml"
	assert_eq "$(yaml_get "$cfg" use_plugin)" "mydht" "use_plugin" || return 1
	assert_eq "$(yaml_get "$cfg" plugins mydht type)" "dhtproxy" "plugins.mydht.type" || return 1
	assert_eq "$(yaml_get "$cfg" plugins mydht proxies 0)" "https://dhtproxy2.jami.net" "plugins.mydht.proxies[0]" || return 1
	assert_eq "$(yaml_get "$cfg" plugins mydht proxies 1)" "https://dhtproxy3.jami.net" "plugins.mydht.proxies[1]"
}

# test_escapes_special_characters is the case that actually exercises
# yaml_quote: a namespace containing a double quote and a backslash,
# values that would otherwise break out of, or be misread inside, a
# YAML double-quoted scalar.
test_escapes_special_characters() {
	[ "$have_python" -eq 1 ] || return 0
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'UCIEOF'
[main]
option namespace weird"ns\name
option node_id alpha
option controller_pubkey pk123
UCIEOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; write_config" 2>"$d/stderr"
	rc=$?
	assert_eq "$rc" "0" "write_config exit code (special characters)" || return 1

	got=$(yaml_get "$d/agent/config.yaml" namespace)
	assert_eq "$got" 'weird"ns\name' "namespace with quote and backslash survives a YAML round trip"
}

test_skips_incomplete_config() {
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'EOF'
[main]
option namespace mymesh
EOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; write_config"
	rc=$?
	assert_eq "$rc" "1" "write_config exit code (incomplete config)" || return 1
	[ -f "$d/agent/config.yaml" ] && { echo "  config.yaml was written despite incomplete config" >&2; return 1; }
	return 0
}

test_skips_missing_uci_file() {
	d=$(scratch)
	write_fake_uci_lib "$d"
	filtered=$(write_filtered "$d")

	UCI_CONFIG_FILE="$d/does-not-exist.conf" $INTERP -c ". $filtered; write_config"
	rc=$?
	assert_eq "$rc" "1" "write_config exit code (no uci file at all)"
}

# --- start_service / reload_service dispatch, with fake procd_* -------

write_fake_procd() {
	d="$1"
	cat > "$d/procd.sh" <<EOF
procd_open_instance() { :; }
procd_close_instance() { :; }
procd_set_param() { echo "\$*" >> "$d/procd-calls"; }
procd_add_reload_trigger() { :; }
EOF
}

write_filtered_with_procd() {
	d="$1"
	out="$d/init-filtered-procd"
	sed \
		-e "s#^\. /lib/functions\.sh\$#. $d/functions.sh; . $d/procd.sh#" \
		-e "s#^CONFIG_DIR=\"/etc/stunmesh/agent\"\$#CONFIG_DIR=\"$d/agent\"#" \
		"$INIT_SCRIPT" > "$out"
	echo "$out"
}

test_start_service_skips_procd_when_not_provisioned() {
	d=$(scratch)
	write_fake_uci_lib "$d"
	write_fake_procd "$d"
	filtered=$(write_filtered_with_procd "$d")

	uci="$d/stunmesh-agent.conf"
	: > "$uci" # empty: no "main" section at all

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; start_service"
	rc=$?
	assert_eq "$rc" "0" "start_service exit code when not provisioned" || return 1
	[ -f "$d/procd-calls" ] && { echo "  procd was invoked despite an unprovisioned node" >&2; return 1; }
	return 0
}

test_start_service_runs_command_with_config_dir() {
	d=$(scratch)
	write_fake_uci_lib "$d"
	write_fake_procd "$d"
	filtered=$(write_filtered_with_procd "$d")

	uci="$d/stunmesh-agent.conf"
	cat > "$uci" <<'EOF'
[main]
option namespace mymesh
option node_id alpha
option controller_pubkey pk123
EOF

	UCI_CONFIG_FILE="$uci" $INTERP -c ". $filtered; start_service"
	rc=$?
	assert_eq "$rc" "0" "start_service exit code when provisioned" || return 1
	[ -f "$d/procd-calls" ] || { echo "  procd_set_param was never called" >&2; return 1; }
	grep -q "command .*stunmesh-agent --config-dir $d/agent" "$d/procd-calls" || {
		echo "  procd-calls = $(cat "$d/procd-calls")" >&2
		return 1
	}
	grep -q "^respawn" "$d/procd-calls"
}

run_test "stunmesh-agent.init: writes minimal config.yaml at mode 0600" test_writes_minimal_config
run_test "stunmesh-agent.init: writes every optional scalar when set" test_writes_optional_scalars
run_test "stunmesh-agent.init: writes use_plugin and its plugins entry" test_writes_use_plugin_and_plugins
run_test "stunmesh-agent.init: escapes quote and backslash in a value" test_escapes_special_characters
run_test "stunmesh-agent.init: skips an incomplete config" test_skips_incomplete_config
run_test "stunmesh-agent.init: skips a missing uci file" test_skips_missing_uci_file
run_test "stunmesh-agent.init: start_service skips procd when not provisioned" test_start_service_skips_procd_when_not_provisioned
run_test "stunmesh-agent.init: start_service runs the daemon with --config-dir" test_start_service_runs_command_with_config_dir

report_and_exit
