#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Signature compilation and management

# Source guard
[[ -n "${_LMD_SIGS_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_SIGS_LOADED=1

# shellcheck disable=SC2034
LMD_SIGS_VERSION="1.0.0"

_count_signatures() {
	local _md5_src="$1" _hex_src="$2"
	md5_sigs=$($wc -l < "$_md5_src")
	sha256_sigs=0
	if [ -f "$sig_sha256_file" ] && [ -s "$sig_sha256_file" ]; then
		sha256_sigs=$($wc -l < "$sig_sha256_file")
	elif [ -n "$runtime_sha256" ] && [ -s "$runtime_sha256" ]; then
		sha256_sigs=$($wc -l < "$runtime_sha256")
	fi
	hex_sigs=$($wc -l < "$_hex_src")
	yara_sigs=$(grep -E -c '^rule ' "$sig_yara_file" 2>/dev/null || true)  # safe: grep exits 1 when no rule match found; zero count is valid
	user_yara_sigs=0
	if [ -f "$sig_user_yara_file" ] && [ -s "$sig_user_yara_file" ]; then
		user_yara_sigs=$((user_yara_sigs + $(grep -E -c '^rule ' "$sig_user_yara_file" 2>/dev/null || true)))  # safe: grep exits 1 when no rule match found; zero count is valid
	fi
	for _yar in "$sig_user_yara_dir"/*.yar "$sig_user_yara_dir"/*.yara; do
		if [ -f "$_yar" ] && [ -s "$_yar" ]; then
			user_yara_sigs=$((user_yara_sigs + $(grep -E -c '^rule ' "$_yar" 2>/dev/null || true)))  # safe: grep exits 1 when no rule match found; zero count is valid
		fi
	done
	if [ ! -f "$sig_user_md5_file" ]; then
		user_md5_sigs=0
	else
		user_md5_sigs=$($wc -l < "$sig_user_md5_file")
	fi
	user_sha256_sigs=0
	if [ -f "$sig_user_sha256_file" ] && [ -s "$sig_user_sha256_file" ]; then
		user_sha256_sigs=$($wc -l < "$sig_user_sha256_file")
	fi
	if [ ! -f "$sig_user_hex_file" ]; then
		user_hex_sigs=0
	else
		user_hex_sigs=$($wc -l < "$sig_user_hex_file")
	fi
	csig_sigs=0
	if [ -f "$sig_csig_file" ] && [ -s "$sig_csig_file" ]; then
		csig_sigs=$(grep -c -vE '^\s*$|^\s*#' "$sig_csig_file" 2>/dev/null || true)  # safe: grep exits 1 when no match; zero count is valid
	fi
	user_csig_sigs=0
	if [ -f "$sig_user_csig_file" ] && [ -s "$sig_user_csig_file" ]; then
		user_csig_sigs=$(grep -c -vE '^\s*$|^\s*#' "$sig_user_csig_file" 2>/dev/null || true)  # safe: grep exits 1 when no match; zero count is valid
	fi
	user_sigs=$((user_hex_sigs + user_md5_sigs + user_sha256_sigs + user_yara_sigs + user_csig_sigs))
	tot_sigs=$((md5_sigs + sha256_sigs + hex_sigs + csig_sigs + yara_sigs + user_sigs))
}

_hex_compile_pattern() {
	# Convert a ClamAV hex pattern to ERE if it contains wildcards.
	# Returns 0 (true) if conversion was needed, 1 (false) if pure literal.
	# Output: ERE pattern on stdout.
	local _pat="$1"
	local _has_wildcard=0
	# Detect ClamAV wildcard tokens: ??, (alt), *, nibble ?x/x?, {N-M} bounded gap
	# Lowercase only — matches sed scope below; od outputs lowercase hex
	local _wc_re='(\?\?|\(.*\|.*\)|\*|\?[0-9a-f]|[0-9a-f]\?|\{[0-9]+-[0-9]+\})'
	if [[ "$_pat" =~ $_wc_re ]]; then
		_has_wildcard=1
	fi
	if [ "$_has_wildcard" == "0" ]; then
		return 1
	fi
	# Convert wildcards to ERE:
	#   ?? → [0-9a-f]{2}  (any byte)
	#   *  → [0-9a-f]*    (variable length)
	#   ?x → [0-9a-f]x    (nibble wildcard, high)
	#   x? → x[0-9a-f]    (nibble wildcard, low)
	#   (aa|bb) → already ERE, passthrough
	local _ere="$_pat"
	# Order matters: ?? before single-nibble ?x
	# Note: $sed on FreeBSD already includes -E; double -E is harmless
	_ere=$(echo "$_ere" | $sed -E 's/\?\?/[0-9a-f]{2}/g')
	# Nibble wildcards: ?x where x is hex digit (high nibble wild)
	_ere=$(echo "$_ere" | $sed -E 's/\?([0-9a-f])/[0-9a-f]\1/g')
	# Nibble wildcards: x? where x is hex digit (low nibble wild)
	_ere=$(echo "$_ere" | $sed -E 's/([0-9a-f])\?/\1[0-9a-f]/g')
	# * → variable length match
	_ere=$(echo "$_ere" | $sed -E 's/\*/[0-9a-f]*/g')
	# {N-M} → bounded gap: N-M bytes = 2N-2M hex chars
	# Bash loop with shell arithmetic (sed cannot multiply, awk match()
	# capture groups are gawk-only — mawk on Ubuntu/Debian lacks them)
	local _gap_re='\{([0-9]+)-([0-9]+)\}'
	while [[ "$_ere" =~ $_gap_re ]]; do
		local _gap_n="${BASH_REMATCH[1]}" _gap_m="${BASH_REMATCH[2]}"
		local _hex_lo=$((_gap_n * 2)) _hex_hi=$((_gap_m * 2))
		local _gap_old="{${_gap_n}-${_gap_m}}"
		local _gap_new="[0-9a-f]{${_hex_lo},${_hex_hi}}"
		_ere="${_ere/"$_gap_old"/$_gap_new}"
	done
	echo "$_ere"
	return 0
}

_csig_compile_subsig() {
	# Compile one csig subsig to ERE, handling i:/w:/iw: prefixes and wildcards.
	# Output: ERE pattern on stdout.
	# Prefix flags:
	#   i: = case-insensitive (fold alpha hex bytes 41-5a to alternation)
	#   w: = wide/UTF-16LE (insert 00 between each hex byte pair)
	#   iw: or wi: = both
	local _raw="$1"
	local _do_icase=0 _do_wide=0

	# Strip prefix flags
	case "$_raw" in
		iw:*|wi:*) _do_icase=1; _do_wide=1; _raw="${_raw#*:}" ;;
		i:*) _do_icase=1; _raw="${_raw#i:}" ;;
		w:*) _do_wide=1; _raw="${_raw#w:}" ;;
	esac

	# Apply wide interleaving: insert 00 between each hex byte pair.
	# Only literal hex bytes are interleaved; wildcards pass through.
	if [ "$_do_wide" == "1" ]; then
		local _wide="" _wpos=0 _wlen=${#_raw}
		while [ "$_wpos" -lt "$_wlen" ]; do
			local _wch="${_raw:_wpos:1}"
			local _wch2="${_raw:_wpos:2}"
			# Check for multi-char wildcard tokens
			if [ "$_wch2" == "??" ]; then
				# ?? wildcard — pass through, add 00 after
				_wide="${_wide}??00"
				_wpos=$((_wpos + 2))
			elif [ "$_wch" == "*" ]; then
				# * wildcard — pass through as-is
				_wide="${_wide}*"
				_wpos=$((_wpos + 1))
			elif [ "$_wch" == "{" ]; then
				# {N-M} bounded gap — double values for wide byte spacing
				local _gap_tok="${_raw:_wpos}"
				_gap_tok="${_gap_tok%%\}*}}"
				# Extract N and M, double them for UTF-16LE (each char = 2 bytes)
				local _gap_inner="${_gap_tok#\{}"
				_gap_inner="${_gap_inner%\}}"
				local _gap_lo="${_gap_inner%-*}"
				local _gap_hi="${_gap_inner#*-}"
				_wide="${_wide}{$((_gap_lo * 2))-$((_gap_hi * 2))}"
				_wpos=$((_wpos + ${#_gap_tok}))
			elif [ "$_wch" == "(" ]; then
				# (alt|alt) group — pass through
				local _alt_tok="${_raw:_wpos}"
				_alt_tok="${_alt_tok%%)*})"
				_wide="${_wide}${_alt_tok}"
				_wpos=$((_wpos + ${#_alt_tok}))
			else
				# Literal hex byte pair or nibble wildcard
				if [ $((_wpos + 2)) -le "$_wlen" ]; then
					_wide="${_wide}${_wch2}00"
					_wpos=$((_wpos + 2))
				else
					# Odd trailing char (shouldn't happen in valid sigs)
					_wide="${_wide}${_wch}"
					_wpos=$((_wpos + 1))
				fi
			fi
		done
		# Remove trailing 00 (last byte doesn't need null separator)
		if [ "${_wide: -2}" == "00" ]; then
			_wide="${_wide%00}"
		fi
		_raw="$_wide"
	fi

	# Compile wildcards to ERE via shared helper
	local _ere
	if _ere=$(_hex_compile_pattern "$_raw"); then
		: # _ere is set from stdout
	else
		_ere="$_raw"
	fi

	# Apply case-folding: for each alpha hex byte 41-5a, generate (XX|xx) alternation
	if [ "$_do_icase" == "1" ]; then
		local _folded="" _fpos=0 _flen=${#_ere}
		while [ "$_fpos" -lt "$_flen" ]; do
			local _fc="${_ere:_fpos:1}"
			# Skip over ERE metachar sequences using pure bash (no sed —
			# $sed prepends -E on FreeBSD which breaks BRE capture groups)
			if [ "$_fc" == "[" ]; then
				# Pass through entire character class [...] as-is
				local _tail="${_ere:_fpos}"
				local _close="${_tail#*]}"
				local _cls_end="${_tail%"$_close"}"
				if [ -n "$_cls_end" ] && [ "$_cls_end" != "$_tail" ]; then
					_folded="${_folded}${_cls_end}"
					_fpos=$((_fpos + ${#_cls_end}))
				else
					_folded="${_folded}${_fc}"
					_fpos=$((_fpos + 1))
				fi
			elif [ "$_fc" == "(" ]; then
				# Pass through ERE groups (...) as-is
				local _tail="${_ere:_fpos}"
				local _close="${_tail#*\)}"
				local _grp_end="${_tail%"$_close"}"
				if [ -n "$_grp_end" ] && [ "$_grp_end" != "$_tail" ]; then
					_folded="${_folded}${_grp_end}"
					_fpos=$((_fpos + ${#_grp_end}))
				else
					_folded="${_folded}${_fc}"
					_fpos=$((_fpos + 1))
				fi
			elif [ "$_fc" == "{" ]; then
				# Pass through quantifiers {N,M} as-is
				local _tail="${_ere:_fpos}"
				local _close="${_tail#*\}}"
				local _qt_end="${_tail%"$_close"}"
				if [ -n "$_qt_end" ] && [ "$_qt_end" != "$_tail" ]; then
					_folded="${_folded}${_qt_end}"
					_fpos=$((_fpos + ${#_qt_end}))
				else
					_folded="${_folded}${_fc}"
					_fpos=$((_fpos + 1))
				fi
			else
				# Check for hex byte pair (two hex chars)
				local _fc2="${_ere:_fpos:2}"
				local _hex_byte_re='^[0-9a-f]{2}$'
				if [[ "$_fc2" =~ $_hex_byte_re ]]; then
					# Check if this is an alpha byte (41-5a = A-Z)
					local _dec
					_dec=$(printf '%d' "0x${_fc2}" 2>/dev/null) || _dec=0
					if [ "$_dec" -ge 65 ] && [ "$_dec" -le 90 ]; then
						# Uppercase alpha — generate (UC|LC) alternation
						local _lc
						_lc=$(printf '%02x' $((_dec + 32)))
						_folded="${_folded}(${_fc2}|${_lc})"
					elif [ "$_dec" -ge 97 ] && [ "$_dec" -le 122 ]; then
						# Lowercase alpha — generate (UC|LC) alternation
						local _uc
						_uc=$(printf '%02x' $((_dec - 32)))
						_folded="${_folded}(${_uc}|${_fc2})"
					else
						_folded="${_folded}${_fc2}"
					fi
					_fpos=$((_fpos + 2))
				else
					_folded="${_folded}${_fc}"
					_fpos=$((_fpos + 1))
				fi
			fi
		done
		_ere="$_folded"
	fi

	echo "$_ere"
}

_csig_classify_subsig() {
	# Classify a compiled subsig ERE and write to the appropriate batch file.
	# $1=SID, $2=ERE, $3=literals_file, $4=wildcards_file, $5=universals_file
	local _sid="$1" _ere="$2" _lit_f="$3" _wc_f="$4" _uni_f="$5"
	# Universal: raw ERE shorter than 8 chars (< 4 bytes hex = zero selectivity)
	if [ "${#_ere}" -lt 8 ]; then
		echo "$_sid" >> "$_uni_f"
		return
	fi
	# Wildcard: contains ERE metacharacters from _hex_compile_pattern output
	# Check for: character class [0-9a-f], alternation group (a|b), or bare alternation |
	local _wc_detect='(\[0-9a-f\]|\(.*\||\|)'
	if [[ "$_ere" =~ $_wc_detect ]]; then
		printf '%d\t%s\n' "$_sid" "$_ere" >> "$_wc_f"
	else
		printf '%d\t%s\n' "$_sid" "$_ere" >> "$_lit_f"
	fi
}

_csig_dedup_subsig() {
	# Assign a unique SID for a compiled ERE. Returns existing SID if pattern
	# was already seen. Sets _result_sid as output (avoids subshell).
	# Uses parallel indexed arrays for bash 4.1 compat (no declare -A).
	# CONTRACT: Must only be called from _csig_compile_rules(). Relies on
	# caller-scope locals: _dedup_eres, _dedup_sids, _dedup_count, _next_sid.
	# Caller must declare: local _result_sid before each call.
	local _ere="$1"
	local _di
	for (( _di=0; _di<_dedup_count; _di++ )); do
		if [ "${_dedup_eres[$_di]}" == "$_ere" ]; then
			_result_sid="${_dedup_sids[$_di]}"
			return 0
		fi
	done
	# New unique ERE
	_result_sid="$_next_sid"
	_dedup_eres[$_dedup_count]="$_ere"
	_dedup_sids[$_dedup_count]="$_next_sid"
	_dedup_count=$((_dedup_count + 1))
	_next_sid=$((_next_sid + 1))
	# Classify and write to tier file (only on first assignment)
	_csig_classify_subsig "$_result_sid" "$_ere" \
		"$runtime_csig_literals" "$runtime_csig_wildcards" "$runtime_csig_universals"
}

_csig_compile_rules() {
	# Parse csig.dat lines and compile to batch-format rule files.
	# Input: $1 = runtime csig file (merged base + custom, ignore-filtered)
	# Output: writes runtime_csig_batch_compiled plus tier files (literals/wildcards/universals).
	# Format: SIGNAME\tTYPE\tTHRESHOLD\tSPEC (SID-referenced)
	local _csig_src="$1"
	local _line _signame _sigs_field _threshold _rule_type
	local _compiled_count=0

	# Batch-format output files
	if [ -n "$runtime_csig_batch_compiled" ]; then
		: > "$runtime_csig_batch_compiled"
		: > "$runtime_csig_literals"
		: > "$runtime_csig_wildcards"
		: > "$runtime_csig_universals"
	fi

	# Subsig dedup: parallel indexed arrays (bash 4.1 — no declare -A)
	local _dedup_eres _dedup_sids _dedup_count=0 _next_sid=0
	_dedup_eres=()
	_dedup_sids=()

	while IFS= read -r _line; do
		# Skip empty lines and comments
		[ -z "$_line" ] && continue
		case "$_line" in \#*) continue ;; esac

		# csig.dat format: SIGS_FIELD:SIGNAME
		# Split on LAST colon — sigs_field may contain i:/w:/iw: prefixes
		# which add early colons. Sig names never contain colons.
		_signame="${_line##*:}"
		_sigs_field="${_line%:*}"
		if [ -z "$_sigs_field" ] || [ -z "$_signame" ]; then
			eout "{csig} WARNING: malformed csig line, skipping: ${_line:0:60}" 1
			continue
		fi

		# Split SIGS_FIELD on top-level || only.
		# Respects parenthesized groups: || inside (...) is NOT a separator.
		local _subsigs _nsubs _paren_depth=0 _current=""
		_subsigs=()
		local _sf_len=${#_sigs_field} _sf_pos=0
		while [ "$_sf_pos" -lt "$_sf_len" ]; do
			local _sf_ch="${_sigs_field:_sf_pos:1}"
			local _sf_ch2="${_sigs_field:_sf_pos:2}"
			if [ "$_sf_ch" == "(" ]; then
				_paren_depth=$((_paren_depth + 1))
				_current="${_current}${_sf_ch}"
				_sf_pos=$((_sf_pos + 1))
			elif [ "$_sf_ch" == ")" ]; then
				_paren_depth=$((_paren_depth - 1))
				_current="${_current}${_sf_ch}"
				_sf_pos=$((_sf_pos + 1))
			elif [ "$_sf_ch2" == "||" ] && [ "$_paren_depth" -eq 0 ]; then
				[ -n "$_current" ] && _subsigs+=("$_current")
				_current=""
				_sf_pos=$((_sf_pos + 2))
			else
				_current="${_current}${_sf_ch}"
				_sf_pos=$((_sf_pos + 1))
			fi
		done
		[ -n "$_current" ] && _subsigs+=("$_current")
		_nsubs=${#_subsigs[@]}

		if [ "$_nsubs" -eq 0 ]; then
			eout "{csig} WARNING: no subsigs in csig line, skipping: ${_line:0:60}" 1
			continue
		fi

		# Determine rule type and threshold
		# Check for OR groups: subsig starting with ( is a grouped OR
		local _has_groups=0 _has_plain=0 _i
		for (( _i=0; _i<_nsubs; _i++ )); do
			case "${_subsigs[$_i]}" in
				"("*) _has_groups=1 ;;
				*) _has_plain=1 ;;
			esac
		done

		if [ "$_nsubs" -eq 1 ] && [ "$_has_groups" -eq 0 ]; then
			_rule_type="single"
			_threshold=1
		elif [ "$_has_groups" -eq 1 ]; then
			_rule_type="group"
			_threshold=0  # AND across top-level elements
		else
			# Check for threshold annotation: first subsig may be N/M format
			# If all subsigs are plain, it's AND (all must match)
			_rule_type="and"
			_threshold=0
		fi

		# Check for threshold prefix on signame: {CSIG}name or threshold:N
		# Threshold encoded in signame as SIGNAME;N (semicolon-separated)
		local _thresh_re=';([0-9]+)$'
		if [[ "$_signame" =~ $_thresh_re ]]; then
			_threshold="${BASH_REMATCH[1]}"
			_signame="${_signame%;*}"
			if [ "$_threshold" -eq 0 ]; then
				eout "{csig} WARNING: threshold=0 produces always-matching rule, skipping: ${_signame}" 1
				continue
			fi
			if [ "$_nsubs" -gt 1 ] && [ "$_has_groups" -eq 0 ]; then
				_rule_type="or"
			fi
		fi

		# Compile each subsig
		local _compile_ok=1
		local _batch_rule_spec=""
		for (( _i=0; _i<_nsubs; _i++ )); do
			local _sub="${_subsigs[$_i]}"

			# Handle grouped OR: (subsig1||subsig2||...);threshold
			case "$_sub" in
			"("*)
				# Parse group: strip parens, extract threshold
				local _grp_body="${_sub#\(}"
				local _grp_thresh=1
				# Check for );N suffix
				local _grp_thresh_re='\);([0-9]+)$'
				if [[ "$_grp_body" =~ $_grp_thresh_re ]]; then
					_grp_thresh="${BASH_REMATCH[1]}"
					_grp_body="${_grp_body%);*}"
				else
					_grp_body="${_grp_body%)}"
				fi
				# Reject group threshold=0 -- matches everything (same as outer guard)
				if [ "$_grp_thresh" -eq 0 ]; then
					eout "{csig} WARNING: group threshold=0 produces always-matching group, skipping rule: ${_signame}" 1
					_compile_ok=0
					break
				fi

				# Split group subsigs on ||
				local _grp_subs _grp_batch_sids=""
				_grp_subs=()
				while IFS= read -r _gsub; do
					[ -n "$_gsub" ] && _grp_subs+=("$_gsub")
				done < <(echo "$_grp_body" | awk -F'\\|\\|' '{for(i=1;i<=NF;i++) print $i}')

				local _gi
				for (( _gi=0; _gi<${#_grp_subs[@]}; _gi++ )); do
					local _gere
					_gere=$(_csig_compile_subsig "${_grp_subs[$_gi]}")
					if [ -z "$_gere" ]; then
						eout "{csig} WARNING: failed to compile group subsig, skipping rule: ${_signame}" 1
						_compile_ok=0
						break 2
					fi
					local _result_sid
					_csig_dedup_subsig "$_gere"
					_grp_batch_sids="${_grp_batch_sids:+${_grp_batch_sids}+}${_result_sid}"
				done

				# Batch format: or:THRESHOLD:SID1+SID2+...
				_batch_rule_spec="${_batch_rule_spec:+${_batch_rule_spec},}or:${_grp_thresh}:${_grp_batch_sids}"
				;;
			*)
				# Plain subsig
				local _ere
				_ere=$(_csig_compile_subsig "$_sub")
				if [ -z "$_ere" ]; then
					eout "{csig} WARNING: failed to compile subsig, skipping rule: ${_signame}" 1
					_compile_ok=0
					break
				fi
				local _result_sid
				_csig_dedup_subsig "$_ere"
				_batch_rule_spec="${_batch_rule_spec:+${_batch_rule_spec},}${_result_sid}"
				;;
			esac
		done

		[ "$_compile_ok" -eq 0 ] && continue

		# Prepend {CSIG} to signame if not already present
		case "$_signame" in
			"{CSIG}"*) ;;
			*) _signame="{CSIG}${_signame}" ;;
		esac

		# Write batch-format rule: SIGNAME\tTYPE\tTHRESHOLD\tSPEC
		printf '%s\t%s\t%s\t%s\n' \
			"$_signame" "$_rule_type" "$_threshold" "$_batch_rule_spec" \
			>> "$runtime_csig_batch_compiled"

		_compiled_count=$((_compiled_count + 1))
	done < "$_csig_src"

	runtime_csig_count=$_compiled_count
}

_hex_lookup_name() {
	# DEPRECATED: all callers removed in lmd_engine.sh (G5, v2.0.1). Remove in v2.0.2.
	# Look up signature name from tab-delimited sigmap file.
	# Uses exact field match (not substring) via awk.
	local _pattern="$1" _sigmap="$2"
	awk -F'\t' -v pat="$_pattern" '$1 == pat { print $2; exit }' "$_sigmap"
}

gensigs() {
	local _silent="$1"
	# Clean up previous runtime sig files if re-called (monitor path)
	rm -f "$runtime_ndb" "$runtime_hdb" "$runtime_hexstrings" "$runtime_md5" \
		"$runtime_sha256" "$runtime_hsb" \
		"$runtime_hex_literal" "$runtime_hex_regex" "$runtime_hex_sigmap" \
		"$runtime_csig_batch_compiled" "$runtime_csig_literals" \
		"$runtime_csig_wildcards" "$runtime_csig_universals" \
		2>/dev/null  # vars empty on first call
	runtime_ndb=$(mktemp "$tmpdir/.runtime.user.ndb.XXXXXX")
	runtime_hdb=""
	runtime_hexstrings=$(mktemp "$tmpdir/.runtime.hexsigs.XXXXXX")
	runtime_md5=$(mktemp "$tmpdir/.runtime.md5sigs.XXXXXX")
	ln -fs "$runtime_ndb" "$sigdir/lmd.user.ndb" 2> /dev/null
	# Only create .hdb (ClamAV MD5 DB) when hashtype includes md5
	if [ "$_effective_hashtype" != "sha256" ]; then
		runtime_hdb=$(mktemp "$tmpdir/.runtime.user.hdb.XXXXXX")
		ln -fs "$runtime_hdb" "$sigdir/lmd.user.hdb" 2> /dev/null
	else
		rm -f "$sigdir/lmd.user.hdb" 2>/dev/null
	fi
	if [ ! -f "$sig_user_yara_file" ]; then
		touch "$sig_user_yara_file"
		chmod $sig_file_mode "$sig_user_yara_file"
	fi
	if [ ! -d "$sig_user_yara_dir" ]; then
		mkdir -p "$sig_user_yara_dir"
		chmod $sig_dir_mode "$sig_user_yara_dir"
	fi
	if [ -s "$sig_user_hex_file" ]; then
		grep -h -vE '^\s*$' "$sig_hex_file" "$sig_user_hex_file" > "$runtime_hexstrings"
	else
		cat "$sig_hex_file" > "$runtime_hexstrings"
	fi
	if [ -s "$sig_user_md5_file" ]; then
		grep -h -vE '^\s*$' "$sig_md5_file" "$sig_user_md5_file" > "$runtime_md5"
	else
		cat "$sig_md5_file" > "$runtime_md5"
	fi
	# SHA-256 runtime sigs — conditional on effective hashtype
	runtime_sha256=""
	if [ "$_effective_hashtype" == "sha256" ] || [ "$_effective_hashtype" == "both" ]; then
		runtime_sha256=$(mktemp "$tmpdir/.runtime.sha256sigs.XXXXXX")
		if [ -f "$sig_sha256_file" ] && [ -s "$sig_sha256_file" ]; then
			if [ -s "$sig_user_sha256_file" ]; then
				grep -h -vE '^\s*$' "$sig_sha256_file" "$sig_user_sha256_file" > "$runtime_sha256"
			else
				cat "$sig_sha256_file" > "$runtime_sha256"
			fi
		elif [ -s "$sig_user_sha256_file" ]; then
			# Upgrade path: no base sha256v2.dat yet, only custom sigs
			grep -vE '^\s*$' "$sig_user_sha256_file" > "$runtime_sha256"
		else
			# No SHA-256 sigs available at all
			: > "$runtime_sha256"
			if [ "$_effective_hashtype" == "sha256" ]; then
				eout "{scan} WARNING: scan_hashtype=sha256 but no SHA-256 signature files found; SHA-256 pass will have zero signatures" 1
			fi
		fi
	fi
	if [ "$scan_clamscan" == "1" ]; then
		if [ -s "$sig_user_hex_file" ]; then
			while IFS= read -r i; do
				name=$(echo "$i" | tr '%' ' ' | awk '{print$2}')
				hex=$(echo "$i" | tr '%' ' ' | awk '{print$1}')
				if [ -n "$name" ] && [ -n "$hex" ]; then
					echo "{HEX}$name:0:*:$hex" >> "$runtime_ndb"
				fi
			done < <(sed 's/{HEX}//' "$sig_user_hex_file" | tr ':' '%' | grep -vE "^\s*$")
			cat "$sig_cav_hex_file" >> "$runtime_ndb"
		else
			command cp "$sig_cav_hex_file" "$runtime_ndb"
		fi
		# ClamAV .hdb (MD5 hash DB) — only when hashtype includes md5
		if [ -n "$runtime_hdb" ]; then
			if [ -s "$sig_user_md5_file" ]; then
				# Convert user MD5 sigs from LMD format (HASH:SIZE:{MD5}name) to ClamAV .hdb format (HASH:SIZE:name)
				sed 's/{MD5}//' "$sig_user_md5_file" | grep -vE "^\s*$" > "$runtime_hdb"
				cat "$sig_cav_md5_file" >> "$runtime_hdb"
			else
				cp "$sig_cav_md5_file" "$runtime_hdb"
			fi
		fi
		# ClamAV .hsb (SHA-256 hash DB) — requires ClamAV >= 0.97
		runtime_hsb=""
		if [ -n "$runtime_sha256" ] && [ -s "$runtime_sha256" ] && [ -n "$_clamav_supports_hsb" ]; then
			runtime_hsb=$(mktemp "$tmpdir/.runtime.user.hsb.XXXXXX")
			if [ -s "$sig_user_sha256_file" ]; then
				sed 's/{SHA256}//' "$sig_user_sha256_file" | grep -vE "^\s*$" > "$runtime_hsb"
				[ -f "$sig_cav_sha256_file" ] && [ -s "$sig_cav_sha256_file" ] && cat "$sig_cav_sha256_file" >> "$runtime_hsb"
			elif [ -f "$sig_cav_sha256_file" ] && [ -s "$sig_cav_sha256_file" ]; then
				cp "$sig_cav_sha256_file" "$runtime_hsb"
			else
				: > "$runtime_hsb"
			fi
			if [ -s "$runtime_hsb" ]; then
				ln -fs "$runtime_hsb" "$sigdir/lmd.user.hsb" 2>/dev/null
			fi
		fi
	fi
	# Copy sigs to ClamAV dirs AFTER runtime user sigs are populated;
	# empty lmd.user.* files cause ClamAV "Malformed database" errors
	for _cpath in $clamav_paths; do
		clamav_linksigs "$_cpath" "scan"
	done

	# Apply ignore_sigs filtering to runtime copies (non-destructive)
	if [ -f "$ignore_sigs" ]; then
		local _ign_count
		_ign_count=$($wc -l < "$ignore_sigs")
		if [ "$_ign_count" != "0" ]; then
			local _tmpfilt
			_tmpfilt=$(mktemp "$tmpdir/.sigfilt.XXXXXX")
			grep -E -vf "$ignore_sigs" "$runtime_hexstrings" > "$_tmpfilt" || true  # safe: grep exits 1 when all sigs ignored; empty output is valid
			cat "$_tmpfilt" > "$runtime_hexstrings"
			grep -E -vf "$ignore_sigs" "$runtime_md5" > "$_tmpfilt" || true  # safe: grep exits 1 when all sigs ignored; empty output is valid
			cat "$_tmpfilt" > "$runtime_md5"
			if [ -n "$runtime_sha256" ] && [ -s "$runtime_sha256" ]; then
				grep -E -vf "$ignore_sigs" "$runtime_sha256" > "$_tmpfilt" || true  # safe: grep exits 1 when all sigs ignored; empty output is valid
				cat "$_tmpfilt" > "$runtime_sha256"
			fi
			rm -f "$_tmpfilt"
			if [ "$_silent" == "1" ] || [ "$hscan" == "1" ]; then
				eout "{glob} processed $_ign_count signature ignore entries"
			else
				eout "{glob} processed $_ign_count signature ignore entries" 1
			fi
		fi
	fi

	# Build native hex scanner lookup files from runtime_hexstrings.
	# Format of runtime_hexstrings: HEXPATTERN:{HEX}sig.name.N (colon-delimited)
	runtime_hex_literal=$(mktemp "$tmpdir/.runtime.hex_literal.XXXXXX")
	runtime_hex_regex=$(mktemp "$tmpdir/.runtime.hex_regex.XXXXXX")
	runtime_hex_sigmap=$(mktemp "$tmpdir/.runtime.hex_sigmap.XXXXXX")
	# Phase 1: Single awk pass — split, build sigmap, classify literal vs wildcard.
	# Wildcard detection: ??, (alt|alt), *, nibble ?x/x?, {N-M} bounded gap.
	# Matches the same regex as _hex_compile_pattern() line 3755.
	local _hex_wc_tmp
	_hex_wc_tmp=$(mktemp "$tmpdir/.hex_wc_tmp.XXXXXX")
	awk -F: -v sigmap="$runtime_hex_sigmap" \
		-v litfile="$runtime_hex_literal" \
		-v wcfile="$_hex_wc_tmp" '
	{
		if (NF < 2 || $0 == "") next
		pat = $1
		# Rejoin fields 2..NF for sig name (name contains {HEX} prefix)
		name = $2
		for (i = 3; i <= NF; i++) name = name ":" $i
		# Sigmap: all patterns
		print pat "\t" name >> sigmap
		# Wildcard detection (ClamAV tokens)
		if (pat ~ /\?\?|\([^)]*\|[^)]*\)|\*|[?][0-9a-f]|[0-9a-f][?]|\{[0-9]+-[0-9]+\}/)
			print pat "\t" name >> wcfile
		else
			print pat >> litfile
	}' "$runtime_hexstrings"
	# Phase 2: Compile wildcards via existing _hex_compile_pattern() (bash).
	# Only ~51 patterns (~2% of total) — costs ~0.1s instead of ~5s.
	local _hex_pat _hex_name _ere
	if [ -s "$_hex_wc_tmp" ]; then
		while IFS=$'\t' read -r _hex_pat _hex_name; do
			if _ere=$(_hex_compile_pattern "$_hex_pat"); then
				printf '%s\t%s\n' "$_hex_pat" "$_ere" >> "$runtime_hex_regex"
			else
				# Classified as wildcard by awk but _hex_compile_pattern says literal
				# (edge case: awk regex is slightly broader than bash regex).
				# Route to literal file — correct behavior.
				echo "$_hex_pat" >> "$runtime_hex_literal"
			fi
		done < "$_hex_wc_tmp"
	fi
	rm -f "$_hex_wc_tmp"

	# Build compound signature (csig) runtime files
	runtime_csig_batch_compiled=""
	runtime_csig_literals=""
	runtime_csig_wildcards=""
	runtime_csig_universals=""
	runtime_csig_count=0
	_gensigs_csig_done=1  # flag: csig compilation attempted (prevents re-trigger loop)
	if [ "$scan_csig" == "1" ]; then
		local _runtime_csig
		_runtime_csig=$(mktemp "$tmpdir/.runtime.csig.XXXXXX")
		if [ -f "$sig_csig_file" ] && [ -s "$sig_csig_file" ]; then
			if [ -f "$sig_user_csig_file" ] && [ -s "$sig_user_csig_file" ]; then
				grep -h -vE '^\s*$' "$sig_csig_file" "$sig_user_csig_file" > "$_runtime_csig"
			else
				cat "$sig_csig_file" > "$_runtime_csig"
			fi
		elif [ -f "$sig_user_csig_file" ] && [ -s "$sig_user_csig_file" ]; then
			grep -vE '^\s*$' "$sig_user_csig_file" > "$_runtime_csig"
		else
			: > "$_runtime_csig"
		fi
		# Apply ignore_sigs filtering to csig
		if [ -f "$ignore_sigs" ] && [ -s "$ignore_sigs" ] && [ -s "$_runtime_csig" ]; then
			local _csig_filt
			_csig_filt=$(mktemp "$tmpdir/.csig_filt.XXXXXX")
			grep -E -vf "$ignore_sigs" "$_runtime_csig" > "$_csig_filt" || true  # safe: grep exits 1 when all sigs ignored; empty output is valid
			cat "$_csig_filt" > "$_runtime_csig"
			rm -f "$_csig_filt"
		fi
		if [ -s "$_runtime_csig" ]; then
			runtime_csig_batch_compiled=$(mktemp "$tmpdir/.runtime.csig_batch_compiled.XXXXXX")
			runtime_csig_literals=$(mktemp "$tmpdir/.runtime.csig_literals.XXXXXX")
			runtime_csig_wildcards=$(mktemp "$tmpdir/.runtime.csig_wildcards.XXXXXX")
			runtime_csig_universals=$(mktemp "$tmpdir/.runtime.csig_universals.XXXXXX")
			_csig_compile_rules "$_runtime_csig"
		fi
		rm -f "$_runtime_csig"
	fi
}
