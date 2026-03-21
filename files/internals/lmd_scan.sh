#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Scan orchestration and pipeline management

# Source guard
[[ -n "${_LMD_SCAN_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_SCAN_LOADED=1

# shellcheck disable=SC2034
LMD_SCAN_VERSION="1.0.0"

_build_scan_filters() {
	# Reset all find-filter variables before rebuilding
	ignore_fext_args=()
	ignore_root=()
	ignore_user=()
	ignore_group=()

	# File extension ignores
	if [ -f "$ignore_file_ext" ] && [ -s "$ignore_file_ext" ]; then
		while IFS= read -r i; do
			ignore_fext_args+=(-not -iname "*$i")
		done < "$ignore_file_ext"
	fi

	# Root-owned file ignores
	if [ "$scan_ignore_root" == "1" ]; then
		ignore_root=(-not -uid 0 -not -gid 0)
	fi

	# Per-user ignores
	if [ "$scan_ignore_user" ]; then
		while IFS= read -r i; do
			if id "$i" >/dev/null 2>&1; then
				ignore_user+=(-not -user "$i")
			else
				eout "{scan} scan_ignore_user: user '$i' does not exist, skipping" 1
			fi
		done < <(echo "$scan_ignore_user" | tr ', ' '\n' | grep -v '^$')
	fi

	# Per-group ignores
	if [ "$scan_ignore_group" ]; then
		while IFS= read -r i; do
			if getent group "$i" >/dev/null 2>&1; then
				ignore_group+=(-not -group "$i")
			else
				eout "{scan} scan_ignore_group: group '$i' does not exist, skipping" 1
			fi
		done < <(echo "$scan_ignore_group" | tr ', ' '\n' | grep -v '^$')
	fi
}

_scan_cleanup() {
	rm -f "$find_results" "$scan_session" "$runtime_ndb" "$runtime_hdb" \
		"$runtime_hexstrings" "$runtime_md5" "$runtime_sha256" "$runtime_hsb" \
		"$clamscan_results" \
		"$runtime_hex_literal" "$runtime_hex_regex" "$runtime_hex_sigmap" \
		"$runtime_csig_batch_compiled" "$runtime_csig_literals" \
		"$runtime_csig_wildcards" "$runtime_csig_universals" \
		"$tmpdir"/.find_killed."$scanid" \
		"$tmpdir"/.tmp* "$tmpdir"/.tmpf* "$tmpdir"/.yara_*."$$".* \
		"$tmpdir"/.hex_batch_flist."$$".* "$tmpdir"/.hex_worker."$$".* "$tmpdir"/.hex_chunk."$$".* \
		"$tmpdir"/.hex_md5hits."$$".* \
		"$tmpdir"/.md5_batch_flist."$$".* "$tmpdir"/.md5_chunk."$$".* "$tmpdir"/.md5_worker."$$".* \
		"$tmpdir"/.md5_linux."$$".* "$tmpdir"/.md5_fbsd."$$".* \
		"$tmpdir"/.sha256_batch_flist."$$".* "$tmpdir"/.sha256_chunk."$$".* "$tmpdir"/.sha256_worker."$$".* \
		"$tmpdir"/.sha256_linux."$$".* "$tmpdir"/.sha256_fbsd."$$".* \
		"$tmpdir"/.sha256_manifest."$$".* "$tmpdir"/.sha256_md5hits."$$".* \
		"$tmpdir"/.batch_* \
		"$tmpdir"/.md5_manifest."$$".* "$tmpdir"/.hex_manifest."$$".* \
		"$tmpdir"/.clam_manifest."$$".* "$tmpdir"/.clam_filtered* \
		"$tmpdir"/.yara_manifest."$$".* "$tmpdir"/.yara_filtered* "$tmpdir"/.yara_existing."$$".* "$tmpdir"/.yara_deduped."$$".* \
		"$tmpdir"/.strlen_manifest."$$".* "$tmpdir"/.stage_hit* \
		"$tmpdir"/.csig_worker* "$tmpdir"/.csig_chunk* "$tmpdir"/.csig_manifest* "$tmpdir"/.csig_batch_flist* \
		"$tmpdir"/.hcb."$$".* "$tmpdir"/.csig_lp."$$".* "$tmpdir"/.csig_ll."$$".* \
		"$tmpdir"/.csig_or."$$".* "$tmpdir"/.csig_all."$$".* \
		"$tmpdir"/.hex_wc_tmp."$$".* "$tmpdir"/.clean_chunk."$$".* \
		2>/dev/null  # files may not exist depending on scan path
	rm -rf "$tmpdir"/.md5_progress.* "$tmpdir"/.hex_progress.* "$tmpdir"/.sha256_progress.* \
		"$tmpdir"/.csig_progress.* "$tmpdir"/.csig_mtx."$$".* 2>/dev/null
}

# shellcheck disable=SC2154
_scan_build_filelist() {
	if [ "$scan_tmpdir_paths" ] && [ -z "$hscan" ] && [ -z "$single_filescan" ]; then
		spath_tmpdirs="$scan_tmpdir_paths"
	fi

	if [ "$file_list" ]; then
		file_list_et=0
		grep -E -vf "$ignore_paths" "$file_list" > "$find_results"
	else
		if [ "$days" == "all" ]; then
			if [ -z "$hscan" ]; then
				eout "{scan} building file list for $hrspath, this might take awhile..." 1
			fi
		else
			rscan=1
			if [ -z "$hscan" ]; then
				eout "{scan} building file list for $hrspath of new/modified files from last $days days, this might take awhile..." 1
			fi
		fi

		if [ -z "$scan_find_timeout" ];then
			scan_find_timeout=0
		fi
		if [ "$scan_find_timeout" -ge "60" ]; then
			lmd_find_sleep=$(mktemp "$tmpdir/.lmd_find_sleep.XXXXXX")
			printf '%s\n' \
				"sleep $scan_find_timeout" \
				"touch \"$tmpdir/.find_killed.$scanid\"" \
				"pkill -f lmd_find_$scanid" \
				"rm -f \"$lmd_find_sleep\"" > "$lmd_find_sleep"
			sh -c "sh \"$lmd_find_sleep\" >> /dev/null 2>&1 &" >> /dev/null 2>&1 &
			eout "{scan} setting maximum execution time for 'find' file list: ${scan_find_timeout}sec" 1
		fi
		if [ -z "$hscan" ]; then
			eout "{scan} setting nice scheduler priorities for all operations: cpunice $scan_cpunice , ionice $scan_ionice" 1
		fi
		file_list_start=$(date +"%s")
		tmpscandir=$(mktemp -d "$tmpdir/scan.XXXXXX")
		chmod 700 "$tmpscandir" ; cd "$tmpscandir" || return 1
		find_prune_args=()
		if [[ -s "$ignore_paths" ]] && [[ -r "$ignore_paths" ]]; then
		    while IFS= read -r ignore_path; do
		        if [[ -n "$ignore_path" && -d "$ignore_path" ]]; then
		            find_prune_args+=(-path "$ignore_path" -prune -o)
		        fi
		    done < "$ignore_paths"
		fi
		if [ "$days" == "all" ]; then
			eout "{scan} executed $nice_command $find $spath $spath_tmpdirs ${find_prune_args[*]} -maxdepth $scan_max_depth $find_opts -type f -size +${scan_min_filesize}c -size -$scan_max_filesize ${include_regex_args[*]} -not -perm 000 ${exclude_regex_args[*]} ${ignore_fext_args[*]} ${ignore_root[*]} ${ignore_user[*]} ${ignore_group[*]}"
			$nice_command "$find" /lmd_find_$scanid/ "${spaths[@]}" $spath_tmpdirs "${find_prune_args[@]}" -maxdepth "$scan_max_depth" $find_opts -type f -size +"${scan_min_filesize}c" -size -"${scan_max_filesize}" "${include_regex_args[@]}" -not -perm 000 "${exclude_regex_args[@]}" "${ignore_fext_args[@]}" "${ignore_root[@]}" "${ignore_user[@]}" "${ignore_group[@]}" 2>/dev/null | grep -E -vf "$ignore_paths" > "$find_results"
		else
			eout "{scan} executed $nice_command $find $spath $spath_tmpdirs ${find_prune_args[*]} -maxdepth $scan_max_depth $find_opts \( -mtime -${days} -o -ctime -${days} \) -type f -size +${scan_min_filesize}c -size -$scan_max_filesize ${include_regex_args[*]} -not -perm 000 ${exclude_regex_args[*]} ${ignore_fext_args[*]} ${ignore_root[*]} ${ignore_user[*]} ${ignore_group[*]}"
			$nice_command "$find" /lmd_find_$scanid/ "${spaths[@]}" $spath_tmpdirs "${find_prune_args[@]}" -maxdepth "$scan_max_depth" $find_opts  \( -mtime -${days} -o -ctime -${days} \) -type f -size +"${scan_min_filesize}c" -size -"${scan_max_filesize}" "${include_regex_args[@]}" -not -perm 000 "${exclude_regex_args[@]}" "${ignore_fext_args[@]}" "${ignore_root[@]}" "${ignore_user[@]}" "${ignore_group[@]}" 2>/dev/null | grep -E -vf "$ignore_paths" > "$find_results"
		fi

		cd "$tmpdir" || true  # safe: tmpscandir cleanup follows regardless
		rm -rf "$tmpscandir"
		if [ "$rscan" = "1" ] && [ "$scan_export_filelist" == "1" ]; then
			rm -f "$tmpdir"/.find_results.* 2> /dev/null
			shared_results=$(mktemp "$tmpdir/.find_results.shared.XXXXXX")
			cp "$find_results" "$shared_results" 2> /dev/null
			ln -fs "$shared_results" "$tmpdir/find_results.last" 2> /dev/null
		fi
		file_list_end=$(date +"%s")
		file_list_et=$((file_list_end - file_list_start))
		if [ -f "$tmpdir/.find_killed.$scanid" ]; then
			rm -f "$tmpdir/.find_killed.$scanid"
			echo && eout "{scan} file list 'find' operation reached maximum execution time (${scan_find_timeout}sec) and was terminated" 1
		else
			pkill -f lmd_find_sleep >> /dev/null 2>&1
		fi
	fi
}

_run_yara_scan() {
	if [ "$scan_yara" == "1" ]; then
		local yara_filelist _yara_file_count
		yara_filelist=$(_yara_filter_filelist "$1")
		_yara_file_count=$($wc -l < "$yara_filelist")
		_scan_progress "yara" "$_yara_file_count files"
		_start_elapsed_timer "yara" "$_yara_file_count"
		scan_stage_yara "$yara_filelist"
		_stop_elapsed_timer
		rm -f "$yara_filelist"
	fi
}

_scan_progress() {
	# Unified scan progress line for all engines and stages.
	# Gated by _in_scan_context to prevent output in monitor/clean paths.
	# Args: stage fileinfo [elapsed]
	local _stage="$1" _fileinfo="$2" _elapsed="$3"
	if [ "$_in_scan_context" == "1" ] && [ -z "$hscan" ] && \
	   [ "$set_background" != "1" ] && [ -z "$single_filescan" ]; then
		local _status=""
		if [ -n "$_elapsed" ]; then
			_status=" | elapsed ${_elapsed}s"
		fi
		local _line="maldet($$): {scan} [$_stage] $_fileinfo${_status} | $progress_hits hits $progress_cleaned cleaned"
		if [ -t 1 ]; then
			# TTY: overwrite current line with cursor-to-column-1 and erase-to-EOL
			printf '\033[%sG\033[K%s' "$res_col" "$_line"
		else
			# Non-TTY (cron, pipe, docker exec): plain newline-terminated output
			echo "$_line"
		fi
	fi
}

_wait_workers_with_progress() {
	# Poll background workers with periodic progress updates.
	# Usage: _wait_workers_with_progress <stage> <file_count> <progress_dir> pids...
	# Reads per-worker progress files from progress_dir to show file-level progress.
	# Updates the scan progress line every 2s with elapsed time and worker count.
	local _stage="$1" _file_count="$2" _progress_dir="$3" _poll_interval=2
	shift 3
	local _pids=("$@")
	local _total=${#_pids[@]}
	local _start_ts _elapsed _running _pid _processed _wpath _wval
	_start_ts=$SECONDS
	while true; do
		_running=0
		for _pid in "${_pids[@]}"; do
			if kill -0 "$_pid" 2>/dev/null; then
				_running=$((_running + 1))
			fi
		done
		_elapsed=$(( SECONDS - _start_ts ))
		# Sum per-worker progress files for file-level progress
		_processed=0
		if [ -d "$_progress_dir" ]; then
			for _wpath in "$_progress_dir"/*; do
				if [ -f "$_wpath" ]; then
					_wval=$(cat "$_wpath" 2>/dev/null)
					if [ -n "$_wval" ] && [ "$_wval" -gt 0 ] 2>/dev/null; then
						_processed=$((_processed + _wval))
					fi
				fi
			done
		fi
		if [ "$_processed" -gt 0 ]; then
			_scan_progress "$_stage" "${_processed}/${_file_count} files" "$_elapsed"
		else
			_scan_progress "$_stage" "$_file_count files" "$_elapsed"
		fi
		if [ "$_running" -eq 0 ]; then
			break
		fi
		sleep "$_poll_interval"
	done
	# Collect exit codes (non-critical)
	for _pid in "${_pids[@]}"; do
		wait "$_pid" 2>/dev/null || true  # worker exit code not critical
	done
	rm -rf "$_progress_dir" 2>/dev/null
}

_start_elapsed_timer() {
	# Start a background elapsed-time progress ticker for single-process stages.
	# Usage: _start_elapsed_timer <stage> <file_count>
	# Sets _timer_pid to the background process PID.
	# Caller must call _stop_elapsed_timer when the stage completes.
	# No-op in background mode to avoid wasted wake-ups.
	_timer_pid=""
	[ "$set_background" == "1" ] && return
	local _stage="$1" _file_count="$2" _start_ts
	_start_ts=$SECONDS
	while true; do
		sleep 2
		_scan_progress "$_stage" "$_file_count files" "$(( SECONDS - _start_ts ))"
	done &
	_timer_pid=$!
}

_stop_elapsed_timer() {
	# Stop the background elapsed-time ticker started by _start_elapsed_timer.
	if [ -n "${_timer_pid:-}" ]; then
		kill "$_timer_pid" 2>/dev/null
		wait "$_timer_pid" 2>/dev/null || true  # suppress "terminated" message
		_timer_pid=""
	fi
}

# shellcheck disable=SC2154
_scan_run_clamav() {
	# Stages: 1+2 ClamAV (hash+hex), 3 YARA, 4 strlen
	if [ -z "$hscan" ]; then
		eout "{scan} found clamav binary at $clamscan, using clamav scanner engine..." 1
	fi
	if [ -z "$hscan" ]; then
		eout "{scan} scan of $hrspath ($tot_files files) in progress..." 1
	fi
	_scan_progress "clamav" "$tot_files files"
	_start_elapsed_timer "clamav" "$tot_files"

	echo "$(date +"%b %d %Y %H:%M:%S") $(hostname -s) clamscan start"  >> "$clamscan_log"
	clamscan_results=$(mktemp "$tmpdir/.clamscan.XXXXXX")
	chmod 600 "$clamscan_results"
	echo "$(date +"%b %d %Y %H:%M:%S") $(hostname -s) executed: $nice_command $clamscan $clamopts --infected --no-summary -f $find_results" >> "$clamscan_log"
	_clamd_retry_scan "$find_results"
	_stop_elapsed_timer
	if [ "$clamscan_return" == "2" ]; then
		if [ "$quarantine_on_error" == "0" ] || [ -z "$quarantine_on_error" ]; then
			quarantine_hits=0
			eout "{scan} clamscan returned an error, check $clamscan_log for details; quarantine_on_error=0 or unset, quarantine has been disabled!" 1
		else
			eout "{scan} clamscan returned an error, check $clamscan_log for details!" 1
		fi
	fi
	clamscan_fatal_error=$(grep -m1 'no reply from clamd' "$clamscan_results")
	if [ "$clamscan_fatal_error" ]; then
		quarantine_hits=0
		eout "{scan} clamscan returned a fatal error in scan results, check $clamscan_log for details; quarantine has been disabled!" 1
	fi
	echo "$(date +"%b %d %Y %H:%M:%S") $(hostname -s) clamscan end return $clamscan_return"  >> "$clamscan_log"
	_process_clamav_hits "$clamscan_results" 1
	_run_yara_scan "$find_results"
	# --- Stage 4: strlen ---
	if [ "$string_length_scan" == "1" ]; then
		if [ -z "$hscan" ]; then
			scan_strlen list "$find_results" >> /dev/null 2>&1
		fi
	fi

	# Final newline after progress ticker
	if [ "$_in_scan_context" == "1" ] && [ -z "$hscan" ] && \
	   [ "$set_background" != "1" ] && [ -z "$single_filescan" ]; then
		echo
	fi
}

_resolve_worker_count() {
	# Resolve the number of parallel workers for scan passes.
	# Arg 1: total file count (workers capped to file count).
	# Outputs resolved count to stdout.
	# Auto-detect: 2 workers per CPU core, capped at 8.
	local _count="${scan_workers:-auto}"
	if [ "$_count" == "auto" ] || [ "$_count" -le 0 ] 2>/dev/null; then  # auto or 0 (legacy)
		_count=$(nproc 2>/dev/null || grep -E -c '^processor' /proc/cpuinfo 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
		_count=$((_count * 2))
		if [ "$_count" -gt 8 ]; then _count=8; fi
	fi
	if [ "$_count" -gt 8 ]; then _count=8; fi
	if [ "$1" -le "$_count" ]; then _count="$1"; fi
	echo "$_count"
}

# shellcheck disable=SC2154
_scan_run_native() {
	# Scan stages (canonical ordering — all paths):
	#   Stage 1:  Hash matching (MD5, SHA-256)     — batch workers
	#   Stage 2:  HEX pattern + CSIG compounds     — batch worker
	#   Stage 3:  YARA rule evaluation              — external engine
	#   Stage 4:  String length analysis            — statistical, per-file
	# Stages are ordered by confidence (high→low) and cost (low→high).
	# Earlier stages quarantine files, reducing the set for later stages.
	local _nworkers
	_nworkers=$(_resolve_worker_count "$tot_files")
	if [ -z "$hscan" ]; then
		# Engine line with hash engine info
		local _hash_desc="$_effective_hashtype hashing"
		if [ "$_sha_capability" == "hardware" ]; then
			_hash_desc="$_hash_desc (hardware sha256-ni)"
		else
			_hash_desc="$_hash_desc (no hardware sha256-ni)"
		fi
		eout "{scan} native engine: $_nworkers workers, $_hash_desc" 1

		# Stage listing: enumerate active scan stages
		local _stage_list=""
		if [ "$_effective_hashtype" == "sha256" ] || [ "$_effective_hashtype" == "both" ]; then
			_stage_list="sha256 hash"
		fi
		if [ "$_effective_hashtype" == "md5" ] || [ "$_effective_hashtype" == "both" ]; then
			_stage_list="${_stage_list:+${_stage_list}, }md5 hash"
		fi
		if [ "$scan_csig" == "1" ] && [ -n "$runtime_csig_batch_compiled" ] && [ -s "$runtime_csig_batch_compiled" ]; then
			_stage_list="${_stage_list:+${_stage_list}, }hex+csig"
		else
			_stage_list="${_stage_list:+${_stage_list}, }hex"
		fi
		if [ "$scan_yara" == "1" ]; then
			_stage_list="${_stage_list:+${_stage_list}, }yara"
		elif [ "$scan_clamscan" == "1" ]; then
			_stage_list="${_stage_list:+${_stage_list}, }yara(cav)"
		fi
		if [ "$string_length_scan" == "1" ]; then
			_stage_list="${_stage_list:+${_stage_list}, }strlen"
		fi
		eout "{scan} stages: $_stage_list" 1
		eout "{scan} scan of $hrspath ($tot_files files) in progress..." 1
	fi
	if [ ! -f "$scan_session" ]; then
		touch "$scan_session"
	fi

	# --- Pass 1: MD5 (batch parallel workers) ---
	# Runs when effective hashtype is md5 or both; skipped for sha256-only.
	local rpath _md5_batch_flist _md5_file_count
	if [ "$_effective_hashtype" == "md5" ] || [ "$_effective_hashtype" == "both" ]; then
		_md5_batch_flist=$(mktemp "$tmpdir/.md5_batch_flist.$$.XXXXXX")
		# Build readable file list from find_results
		while IFS= read -r rpath; do
			[ -f "$rpath" ] && [ -r "$rpath" ] && printf '%s\n' "$rpath"
		done < "$find_results" > "$_md5_batch_flist"
		_md5_file_count=$($wc -l < "$_md5_batch_flist")
		if [ "$_md5_file_count" -gt 0 ] && [ -s "$runtime_md5" ]; then
			_nworkers=$(_resolve_worker_count "$_md5_file_count")
			_scan_progress "md5" "$_md5_file_count files"
			if [ "$_nworkers" -le 1 ]; then
				# Single worker: run inline (no subshell overhead)
				_hash_batch_worker "$md5sum" "md5" "$_md5_batch_flist" "$runtime_md5" > "$tmpdir/.md5_worker.$$.0"
			else
				# Multi-worker: round-robin split and background
				local _md5_chunk_prefix _w _md5_progress_dir _md5_pfile
				_md5_chunk_prefix="$tmpdir/.md5_chunk.$$"
				_md5_progress_dir=$(mktemp -d "$tmpdir/.md5_progress.$$.XXXXXX")
				awk -v n="$_nworkers" -v prefix="$_md5_chunk_prefix" \
					'{ print > (prefix "." ((NR-1) % n)) }' "$_md5_batch_flist"
				local _md5_worker_pids
				_md5_worker_pids=()
				_w=0
				while [ "$_w" -lt "$_nworkers" ]; do
					if [ -f "$_md5_chunk_prefix.$_w" ]; then
						# Skip progress writes in background mode for max throughput
						_md5_pfile=""
						[ "$set_background" != "1" ] && _md5_pfile="$_md5_progress_dir/$_w"
						_hash_batch_worker "$md5sum" "md5" "$_md5_chunk_prefix.$_w" "$runtime_md5" \
							"$_md5_pfile" \
							> "$tmpdir/.md5_worker.$$.${_w}" 2>/dev/null &  # suppress worker file-access stderr
						_md5_worker_pids[_w]=$!
					fi
					_w=$((_w + 1))
				done
				_wait_workers_with_progress "md5" "$_md5_file_count" "$_md5_progress_dir" "${_md5_worker_pids[@]}"
				rm -f "$_md5_chunk_prefix".* 2>/dev/null
			fi
			# Merge worker outputs into single manifest and batch-process hits
			_scan_progress "md5" "processing hits"
			local _md5_manifest
			_md5_manifest=$(mktemp "$tmpdir/.md5_manifest.$$.XXXXXX")
			for _w in "$tmpdir"/.md5_worker."$$".*; do
				if [ -f "$_w" ] && [ -s "$_w" ]; then
					# Worker output: filepath\thash\tsigname → manifest: filepath\tsigname\thash
					awk -F'\t' '{print $1 "\t" $3 "\t" $2}' "$_w" >> "$_md5_manifest"
				fi
			done
			_flush_hit_batch "$_md5_manifest" "md5"
			rm -f "$_md5_manifest" "$tmpdir"/.md5_worker."$$".* 2>/dev/null
		fi
		rm -f "$_md5_batch_flist"
	fi

	# --- Pass 1b: SHA-256 (batch parallel workers) ---
	# Runs instead of MD5 when _effective_hashtype=sha256,
	# or after MD5 when _effective_hashtype=both (on remaining files).
	if { [ "$_effective_hashtype" == "sha256" ] || [ "$_effective_hashtype" == "both" ]; } \
	   && [ -n "$runtime_sha256" ] && [ -s "$runtime_sha256" ]; then
		local _sha256_batch_flist _sha256_file_count
		_sha256_batch_flist=$(mktemp "$tmpdir/.sha256_batch_flist.$$.XXXXXX")
		if [ "$_effective_hashtype" == "both" ]; then
			# 'both' mode: scan only files NOT already hit by MD5 pass
			local _hash_hit_paths
			_hash_hit_paths=$(mktemp "$tmpdir/.sha256_md5hits.$$.XXXXXX")
			if [ -s "$scan_session" ]; then
				awk -F'\t' '!/^#/{if ($2 != "") print $2}' "$scan_session" > "$_hash_hit_paths"
			fi
			while IFS= read -r rpath; do
				[ -f "$rpath" ] && [ -r "$rpath" ] && printf '%s\n' "$rpath"
			done < "$find_results" | {
				if [ -s "$_hash_hit_paths" ]; then
					grep -vFxf "$_hash_hit_paths"
				else
					cat
				fi
			} > "$_sha256_batch_flist"
			rm -f "$_hash_hit_paths"
		else
			# sha256-only mode: scan all readable files
			while IFS= read -r rpath; do
				[ -f "$rpath" ] && [ -r "$rpath" ] && printf '%s\n' "$rpath"
			done < "$find_results" > "$_sha256_batch_flist"
		fi
		_sha256_file_count=$($wc -l < "$_sha256_batch_flist")
		if [ "$_sha256_file_count" -gt 0 ]; then
			_nworkers=$(_resolve_worker_count "$_sha256_file_count")
			_scan_progress "sha256" "$_sha256_file_count files"
			if [ "$_nworkers" -le 1 ]; then
				_hash_batch_worker "$sha256sum" "sha256" "$_sha256_batch_flist" "$runtime_sha256" > "$tmpdir/.sha256_worker.$$.0"
			else
				local _sha256_chunk_prefix _w _sha256_progress_dir _sha256_pfile
				_sha256_chunk_prefix="$tmpdir/.sha256_chunk.$$"
				_sha256_progress_dir=$(mktemp -d "$tmpdir/.sha256_progress.$$.XXXXXX")
				awk -v n="$_nworkers" -v prefix="$_sha256_chunk_prefix" \
					'{ print > (prefix "." ((NR-1) % n)) }' "$_sha256_batch_flist"
				local _sha256_worker_pids
				_sha256_worker_pids=()
				_w=0
				while [ "$_w" -lt "$_nworkers" ]; do
					if [ -f "$_sha256_chunk_prefix.$_w" ]; then
						_sha256_pfile=""
						[ "$set_background" != "1" ] && _sha256_pfile="$_sha256_progress_dir/$_w"
						_hash_batch_worker "$sha256sum" "sha256" "$_sha256_chunk_prefix.$_w" "$runtime_sha256" \
							"$_sha256_pfile" \
							> "$tmpdir/.sha256_worker.$$.${_w}" 2>/dev/null &  # suppress worker file-access stderr
						_sha256_worker_pids[_w]=$!
					fi
					_w=$((_w + 1))
				done
				_wait_workers_with_progress "sha256" "$_sha256_file_count" "$_sha256_progress_dir" "${_sha256_worker_pids[@]}"
				rm -f "$_sha256_chunk_prefix".* 2>/dev/null
			fi
			# Merge worker outputs into single manifest and batch-process hits
			_scan_progress "sha256" "processing hits"
			local _sha256_manifest
			_sha256_manifest=$(mktemp "$tmpdir/.sha256_manifest.$$.XXXXXX")
			for _w in "$tmpdir"/.sha256_worker."$$".*; do
				if [ -f "$_w" ] && [ -s "$_w" ]; then
					# Worker output: filepath\thash\tsigname → manifest: filepath\tsigname\thash
					awk -F'\t' '{print $1 "\t" $3 "\t" $2}' "$_w" >> "$_sha256_manifest"
				fi
			done
			_flush_hit_batch "$_sha256_manifest" "sha256"
			rm -f "$_sha256_manifest" "$tmpdir"/.sha256_worker."$$".* 2>/dev/null
		fi
		rm -f "$_sha256_batch_flist"
	fi

	# --- Pass 2: HEX batch (parallel workers) ---
	local _hex_filelist _hex_depth
	_hex_filelist=$(mktemp "$tmpdir/.hex_batch_flist.$$.XXXXXX")
	# Build file list: skip files already hit by hash passes (MD5/SHA-256).
	# Quarantined files are chmod 000 (not readable); non-quarantined hits
	# are listed in scan_session — extract paths and use grep -vFf to exclude.
	local _hash_hit_paths
	_hash_hit_paths=$(mktemp "$tmpdir/.hex_md5hits.$$.XXXXXX")
	if [ -s "$scan_session" ]; then
		awk -F'\t' '!/^#/{if ($2 != "") print $2}' "$scan_session" > "$_hash_hit_paths"
	fi
	while IFS= read -r rpath; do
		[ -f "$rpath" ] && [ -r "$rpath" ] && printf '%s\n' "$rpath"
	done < "$find_results" | {
		if [ -s "$_hash_hit_paths" ]; then
			grep -vFxf "$_hash_hit_paths"
		else
			cat
		fi
	} > "$_hex_filelist"
	rm -f "$_hash_hit_paths"
	local _hex_file_count
	_hex_file_count=$($wc -l < "$_hex_filelist")
	local _has_hex_sigs=0 _has_csig_sigs=0
	{ [ -s "$runtime_hex_literal" ] || [ -s "$runtime_hex_regex" ]; } && _has_hex_sigs=1
	[ "$scan_csig" == "1" ] && [ -n "$runtime_csig_batch_compiled" ] && [ -s "$runtime_csig_batch_compiled" ] && _has_csig_sigs=1
	local _hex_stage_label="hex"
	[ "$_has_csig_sigs" -eq 1 ] && _hex_stage_label="hex+csig"
	if [ "$_hex_file_count" -gt 0 ] && { [ "$_has_hex_sigs" -eq 1 ] || [ "$_has_csig_sigs" -eq 1 ]; }; then
		# Determine hex depth
		_hex_depth="${scan_hexdepth:-524288}"
		# Resolve worker count
		_nworkers=$(_resolve_worker_count "$_hex_file_count")
		_scan_progress "$_hex_stage_label" "$_hex_file_count files"
		# Split file list into chunks via awk round-robin
		local _chunk_prefix _w
		_chunk_prefix="$tmpdir/.hex_chunk.$$"
		awk -v n="$_nworkers" -v prefix="$_chunk_prefix" '{ print > (prefix "." ((NR-1) % n)) }' "$_hex_filelist"
		# Launch workers and collect PIDs
		local _worker_pids _worker_outputs _wout _hex_progress_dir _hex_pfile
		_worker_pids=()
		_worker_outputs=()
		_hex_progress_dir=$(mktemp -d "$tmpdir/.hex_progress.$$.XXXXXX")
		_w=0
		while [ "$_w" -lt "$_nworkers" ]; do
			_wout="$tmpdir/.hex_worker.$$.${_w}"
			if [ -f "$_chunk_prefix.$_w" ]; then
				# Skip progress writes in background mode for max throughput
				_hex_pfile=""
				[ "$set_background" != "1" ] && _hex_pfile="$_hex_progress_dir/$_w"
				_hex_csig_batch_worker "$_chunk_prefix.$_w" "$_hex_depth" \
					"$runtime_hex_literal" "$runtime_hex_regex" "$runtime_hex_sigmap" \
					"$runtime_csig_batch_compiled" "$runtime_csig_literals" \
					"$runtime_csig_wildcards" "$runtime_csig_universals" \
					"$_hex_pfile" \
					> "$_wout" 2>/dev/null &  # suppress worker file-access stderr
				_worker_pids[_w]=$!
				_worker_outputs[_w]="$_wout"
			fi
			_w=$((_w + 1))
		done
		# Wait for all workers with progress updates
		_wait_workers_with_progress "$_hex_stage_label" "$_hex_file_count" "$_hex_progress_dir" "${_worker_pids[@]}"
		# Merge worker outputs into single manifest and batch-process hits
		_scan_progress "$_hex_stage_label" "processing hits"
		local _hex_manifest
		_hex_manifest=$(mktemp "$tmpdir/.hex_manifest.$$.XXXXXX")
		for _wout in "${_worker_outputs[@]}"; do
			if [ -f "$_wout" ] && [ -s "$_wout" ]; then
				cat "$_wout" >> "$_hex_manifest"
			fi
		done
		_flush_hit_batch "$_hex_manifest" "$_hex_stage_label"
		# Cleanup chunk, worker output, and manifest files
		rm -f "$_hex_manifest" "$_chunk_prefix".* "$tmpdir"/.hex_worker."$$".* 2>/dev/null
	fi

	# --- Stage 3: YARA ---
	_run_yara_scan "$find_results"

	# --- Stage 4: strlen (per-file, on hash-miss files) ---
	# Most expensive stage, most false-positive prone — runs last.
	# Per-file mode handles paths with spaces correctly.
	if [ "$string_length_scan" == "1" ] && [ -s "$_hex_filelist" ]; then
		local _strlen_count
		_strlen_count=$($wc -l < "$_hex_filelist")
		_scan_progress "strlen" "$_strlen_count files"
		while IFS= read -r rpath; do
			if [ -f "$rpath" ]; then
				scan_strlen file "$rpath" >> /dev/null 2>&1
			fi
		done < "$_hex_filelist"
	fi
	rm -f "$_hex_filelist"

	# Final newline after progress ticker
	if [ "$_in_scan_context" == "1" ] && [ -z "$hscan" ] && \
	   [ "$set_background" != "1" ] && [ -z "$single_filescan" ]; then
		echo
	fi
}


scan() {
	scan_start_hr=$(date +"%b %e %Y %H:%M:%S %z")
	scan_start=$(date +"%s")
	spaths_str=$(echo "$1" | tr '?' '*' | tr ',' '\n')
	spaths=()
	while IFS= read -r pattern; do
	  [ -z "$pattern" ] && continue
	  expanded=( $pattern )
	  spaths+=( "${expanded[@]}" )
	done <<< "$spaths_str"
	days="$2"
	scanid="$datestamp.$$"
	if [ "$file_list" ]; then
		spath="\"$file_list\""
	elif [ ! -f "$find" ]; then
		eout "{scan} could not locate find command" 1
		exit 1
	fi
	if [ -f "$spath" ] && [ -z "$file_list" ]; then
		single_filescan=1
	fi
	
	if [ ! -f "$sig_md5_file" ]; then
		eout "{scan} required signature file not found ($sig_md5_file), try running -u|--update, aborting!" 1
		exit 1
	fi
	if [ ! -f "$sig_hex_file" ]; then
		eout "{scan} required signature file not found ($sig_hex_file), try running -u|--update, aborting!" 1
		exit 1
	fi
	if [ ! -f "$ignore_paths" ]; then
		touch "$ignore_paths"
		chmod 640 "$ignore_paths"
	fi
	if [ ! -f "$ignore_sigs" ]; then
		touch "$ignore_sigs"
		chmod 640 "$ignore_sigs"
	fi
		
	if [ "$days" != "all" ] && [ -z "$file_list" ]; then
		if [[ "$days" =~ [[:alpha:]] ]]; then
			eout "{scan} days value must be numeric value in the range of 1 - 90, reverting to default (7)." 1
			days=7
		elif [ "$days" -lt "1" ] || [ "$days" -gt "90" ]; then
			eout "{scan} days value must be numeric value in the range of 1 - 90, reverting to default (7)." 1
			days=7
		fi
	fi
	
	local _spaths_exist=0
	for p in "${spaths[@]}"; do
	  if [ "${p:0:1}" != "/" ]; then
	    eout "{scan} must use absolute path, provided relative path '$p'" 1
	    exit 1
	  fi
	  [ -e "$p" ] && _spaths_exist=$((_spaths_exist + 1))
	done

	scan_session=$(mktemp "$tmpdir/.sess.XXXXXX")
	find_results=$(mktemp "$tmpdir/.find.XXXXXX")

	# Resolve hash engine after -co overrides have been applied
	_resolve_hashtype
	_resolve_clamscan
	_resolve_yara

	# Pre-gensigs signature preview: count from on-disk files (fast, no compilation)
	_count_signatures "$sig_md5_file" "$sig_hex_file"
	local _gensigs_preview_types="hash"
	[ "$hex_sigs" -gt 0 ] && _gensigs_preview_types="${_gensigs_preview_types} hex"
	{ [ "$csig_sigs" -gt 0 ] || [ "$user_csig_sigs" -gt 0 ]; } && _gensigs_preview_types="${_gensigs_preview_types} csig"
	{ [ "$yara_sigs" -gt 0 ] || [ "$user_yara_sigs" -gt 0 ]; } && _gensigs_preview_types="${_gensigs_preview_types} yara"
	if [ -z "$hscan" ]; then
		eout "{scan} compiling $(_format_number $tot_sigs) signatures (${_gensigs_preview_types})..." 1
	fi

	local _gensigs_start=$SECONDS
	gensigs
	local _gensigs_elapsed=$(( SECONDS - _gensigs_start ))
	if [ "$scan_clamscan" == "1" ]; then
		clamselector
	fi

	# Re-count from runtime files (may differ from preview due to custom sig merging)
	_count_signatures "$runtime_md5" "$runtime_hexstrings"
	if [ -z "$hscan" ]; then
		eout "{scan} signatures ready in ${_gensigs_elapsed}s: $(_format_number $tot_sigs) ($(_format_number $hash_sigs) $_hash_label | $(_format_number $hex_sigs) HEX | $(_format_number $csig_sigs) CSIG | $(_format_number $yara_sigs) $_yara_label | $(_format_number $user_sigs) USER)" 1
	fi
	_build_scan_filters
	_scan_build_filelist
	if [ ! -f "$find_results" ] || [ ! -s "$find_results" ]; then
		if [ -z "$hscan" ]; then
			if [ "$days" == "all" ]; then
				eout "{scan} scan returned empty file list; check that path exists and contains files in scope of configuration." 1
				_scan_cleanup
				[ "$_spaths_exist" -eq 0 ] && exit 1
				exit 0
			else
				eout "{scan} scan returned empty file list; check that path exists, contains files in days range or files in scope of configuration." 1
				_scan_cleanup
				[ "$_spaths_exist" -eq 0 ] && exit 1
				exit 0
			fi
		fi
	fi
	
	res_col="1"
	tot_files=$($wc -l < "$find_results")
	if [ -z "$hscan" ] && [ -z "$single_filescan" ]; then
		if [ "$file_list" ]; then
			eout "{scan} user supplied file list '$file_list', found $tot_files files..." 1
		else
			eout "{scan} file list completed in ${file_list_et}s, found $tot_files files..." 1
		fi
	fi
	touch "$sessdir/clean.$$"
	if [ ! -f "$scan_session" ]; then
		touch "$scan_session"
	fi
	progress_hits=0
	progress_cleaned=0
	_in_scan_context=1
	_lmd_elog_event "$ELOG_EVT_SCAN_STARTED" "info" "scan started on $hrspath" "path=$hrspath" "mode=${svc:-a}"

	if [ -n "$hscan" ]; then
		eout "{scan.hook} scan of $spath in progress (id: $datestamp.$$)"
	fi
	cnt=0
	if [ -z "$mail" ] && [ -z "$sendmail" ]; then
		eout "{scan} no \$mail or \$sendmail binaries found, e-mail alerts disabled."
	fi
	if [ -f "$clamscan" ] && [ "$scan_clamscan" == "1" ]; then
		_scan_run_clamav
	else
		_scan_run_native
	fi

	scan_end_hr=$(date +"%b %e %Y %H:%M:%S %z")
	scan_end=$(date +"%s")
	scan_et=$((scan_end - scan_start))
	scan_et_nofl=$((scan_et - file_list_et))
	tot_hits="$progress_hits"
	tot_cl="$progress_cleaned"
	_scan_finalize_session

	if [ -n "$hscan" ]; then
		if [ "$tot_hits" != "0" ]; then
			echo "0 maldet: $hitname $spath"
			eout "{scan.hook} results returned FAIL hit found on $spath (id: $datestamp.$$)"
		else
			echo "1 maldet: OK"
			eout "{scan.hook} results returned OK on $spath (id: $datestamp.$$)"
		fi
	else
		echo
		eout "{scan} scan completed on $hrspath: files $tot_files, malware hits $tot_hits, cleaned hits $tot_cl, time ${scan_et}s" 1
		eout "{scan} scan report saved, to view run: maldet --report $datestamp.$$" 1
		if [ "$quarantine_hits" == "0" ] && [ "$tot_hits" != "0" ]; then
			eout "{scan} quarantine is disabled! set quarantine_hits=1 in $cnffile or to quarantine results run: maldet -q $datestamp.$$" 1
		fi
	fi
	_lmd_elog_event "$ELOG_EVT_SCAN_COMPLETED" "info" "scan completed on $hrspath" "hits=$tot_hits" "files=$tot_files" "cleaned=$tot_cl" "time=${scan_et}s"

	if [ "$tot_hits" != "0" ]; then
		if [ "$email_ignore_clean" == "1" ] && [ "$tot_hits" != "$tot_cl" ]; then
			genalert file "$nsess"
		elif [ "$email_ignore_clean" == "0" ]; then
			genalert file "$nsess"
		fi
		if [ "$email_panel_user_alerts" == "1" ]; then
			genalert panel "$nsess"
		fi
	fi
	_scan_cleanup
}
