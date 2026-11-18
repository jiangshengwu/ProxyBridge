#!/usr/bin/env bash
set -euo pipefail
# Portable LLVM-MinGW build. Run from WSL/Linux with TOOLCHAIN and WINDIVERT set.
# BUILD_RELEASE=0 builds tests only; BUILD_TESTS=0 builds release binaries only.
cd "$(dirname "${BASH_SOURCE[0]}")"
TC="${TOOLCHAIN:?Set TOOLCHAIN to the LLVM-MinGW directory}/bin"
WD="${WINDIVERT:?Set WINDIVERT to the extracted WinDivert SDK}"
CC="$TC/x86_64-w64-mingw32-clang"
RC="$TC/x86_64-w64-mingw32-windres"
OUT="${OUTPUT_DIR:-$PWD/output/mingw-x64}"
TEST="${TEST_DIR:-$PWD/tests/out/mingw-x64}"
mkdir -p "$OUT" "$TEST"
CORE=(src/ProxyBridge.c src/pb_util.c src/pb_process.c src/pb_rules.c src/pb_proxy.c src/pb_dns.c src/pb_dns_proxy.c src/pb_socks5.c src/pb_http.c src/pb_conntrack.c src/pb_relay.c src/pb_sockmap.c)
CFLAGS=(-D_WIN32_WINNT=0x0601 -D_CRT_SECURE_NO_WARNINGS -Wno-unknown-pragmas -fms-extensions)
CORE_FLAGS=(-DPROXYBRIDGE_EXPORTS -Isrc -I"$WD/include")
CORE_LIBS=(-L"$WD/x64" -lWinDivert -lws2_32 -liphlpapi -ladvapi32)
GUI_LIBS=(-luser32 -lgdi32 -lcomctl32 -lshell32 -lcomdlg32 -lwinhttp -ladvapi32 -ldwmapi -luxtheme -lole32 -luuid)
(cd gui/res; "$RC" app.rc -O coff -o "$TEST/app.res")
if [[ "${BUILD_TESTS:-1}" == 1 ]]; then
CORE_OBJS=()
for path in "${CORE[@]}"; do
    obj="$TEST/$(basename "${path%.c}").o"
    "$CC" -O1 -g "${CFLAGS[@]}" "${CORE_FLAGS[@]}" -c "$path" -o "$obj"
    CORE_OBJS+=("$obj")
done
for path in tests/test_*.c tests/core_tests.c tests/gui_tests.c; do
    name="${path##*/}"; name="${name%.c}"
    echo "Building $name"
    extra=(); libs=(); flags=()
    case "$name" in
      test_engine|test_rules_match|test_conntrack|test_flows|test_dns|test_dns_proxy|test_proxy_protocols|core_tests)
        extra=("${CORE_OBJS[@]}"); flags=("${CORE_FLAGS[@]}"); libs=("${CORE_LIBS[@]}");;
      test_hosts|test_profile) extra=(gui/profile/profile.c); flags=(-DUNICODE -D_UNICODE); libs=(-luser32 -ladvapi32 -lshell32);;
      test_json|test_proto) ;;
      test_service) flags=(-DUNICODE -D_UNICODE); libs=(-luser32 -ladvapi32 -lnetapi32 -lwtsapi32);;
      test_cli) libs=(-lwinhttp -lshell32 -ladvapi32);;
      *) extra=(gui/profile/profile.c "$TEST/app.res"); flags=(-DUNICODE -D_UNICODE); libs=("${GUI_LIBS[@]}");
         if [[ "$name" != gui_tests ]]; then flags+=(-municode); fi;;
    esac
    "$CC" -O1 -g "${CFLAGS[@]}" "${flags[@]}" -Itests "$path" "${extra[@]}" "${libs[@]}" -o "$TEST/$name.exe"
done
cp "$WD/x64/WinDivert.dll" "$TEST/"
fi
if [[ "${BUILD_RELEASE:-1}" != 1 ]]; then exit 0; fi
echo 'Building release binaries'
RELEASE=(-O2 -flto -DNDEBUG -ffunction-sections -fdata-sections -mguard=cf -fstack-protector-strong -Wl,--gc-sections,--strip-all,--dynamicbase,--nxcompat,--high-entropy-va)
"$RC" src/core.rc -O coff -o "$TEST/core.res"
"$RC" cli/cli.rc -O coff -o "$TEST/cli.res"
"$RC" src/service/svc.rc -O coff -o "$TEST/svc.res"
"$CC" "${CFLAGS[@]}" "${RELEASE[@]}" "${CORE_FLAGS[@]}" -shared "${CORE[@]}" "$TEST/core.res" "${CORE_LIBS[@]}" -o "$OUT/ProxyBridgeCore.dll"
"$CC" "${CFLAGS[@]}" "${RELEASE[@]}" -DUNICODE -D_UNICODE -municode -mwindows gui/main.c gui/profile/profile.c "$TEST/app.res" "${GUI_LIBS[@]}" -o "$OUT/ProxyBridge.exe"
"$CC" "${CFLAGS[@]}" "${RELEASE[@]}" cli/main.c "$TEST/cli.res" -lwinhttp -lshell32 -ladvapi32 -o "$OUT/ProxyBridge_CLI.exe"
"$CC" "${CFLAGS[@]}" "${RELEASE[@]}" -DUNICODE -D_UNICODE -municode src/service/pb_service.c "$TEST/svc.res" -ladvapi32 -lnetapi32 -lwtsapi32 -luser32 -o "$OUT/ProxyBridgeSvc.exe"
cp "$WD/x64/WinDivert.dll" "$WD/x64/WinDivert64.sys" "$OUT/"
