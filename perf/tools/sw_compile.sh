#!/usr/bin/env bash
# Compile one P4 program with bf-p4c on the switch into its own directory,
# never into the shared $SDE_INSTALL tree. Runs on the switch, under nohup.
#
#   sw_compile.sh SRC_DIR MAIN_P4 OUT_DIR [extra bf-p4c args, e.g. -DFOO=0]
#
# OUT_DIR/compile.log gets bf-p4c's stdout+stderr. OUT_DIR/compile_meta.txt
# records the UTC start/end, compiler version, exact command, SHA-256 of the
# sources, exit code, wall/user/sys seconds and the peak RSS of the compiler
# process tree (sampled once per second). OUT_DIR/.done is written last.
set -u
if [ $# -lt 3 ]; then
    echo "usage: $0 SRC_DIR MAIN_P4 OUT_DIR [bf-p4c args...]" >&2
    exit 2
fi
src=$1; main=$2; out=$3; shift 3
source /root/P4_labs/lab2/config_env.sh > /dev/null 2>&1
mkdir -p "$out"
rm -f "$out/.done"
meta=$out/compile_meta.txt
flags=(--target tofino --arch tna --std p4-16 -g --verbose 2 --log-hashes
       --parser-timing-reports --bf-rt-schema "$out/bf-rt.json" -o "$out" "$@")

# Total RSS (KiB) of process $1 and all of its descendants.
tree_rss() {
    ps -eo pid=,ppid=,rss= | awk -v root="$1" '
        { pp[$1] = $2; r[$1] = $3 }
        END {
            for (p in pp) {
                q = p
                while (q != "" && q != root && q > 1) q = pp[q]
                if (q == root) s += r[p]
            }
            print s + 0
        }'
}

{
    echo "start_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
    echo "host: $(hostname)"
    echo "compiler: $(command -v bf-p4c) ($(bf-p4c --version 2>&1 | head -1))"
    echo "src_dir: $src"
    echo "cmd: cd $src && bf-p4c ${flags[*]} $main"
    echo "sources_sha256:"
    (cd "$src" && sha256sum -- *.p4 | sed 's/^/  /')
} > "$meta"

cd "$src" || exit 1
(
    TIMEFORMAT='wall_s: %R  user_s: %U  sys_s: %S'
    time bf-p4c "${flags[@]}" "$main" > "$out/compile.log" 2>&1
) 2> "$out/.time" &
pid=$!
peak=0
while kill -0 "$pid" 2> /dev/null; do
    rss=$(tree_rss "$pid")
    [ "$rss" -gt "$peak" ] && peak=$rss
    sleep 1
done
# The subshell exits with bf-p4c's status (the time keyword preserves it).
wait "$pid"; rc=$?
{
    echo "end_utc: $(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
    echo "exit_code: $rc"
    cat "$out/.time"
    echo "peak_rss_kib: $peak"
} >> "$meta"
rm -f "$out/.time"
echo "$rc" > "$out/.done"
exit "$rc"
