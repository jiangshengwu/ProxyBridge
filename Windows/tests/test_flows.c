// test_flows.c - live connections in the engine: the relay (src\pb_relay.c) really forwards bytes between two
// loopback socket pairs, and the flow list that ProxyBridge_GetFlows() returns follows it:
//   - a proxied TCP connection appears with its owner (pid + process name), destination and proxy id
//   - the Sent / Received counters equal the bytes that were forwarded in each direction
//   - FIN closes only that direction; delayed reverse data is drained before final cleanup
//   - reset and pool stop still cancel both directions, without leaks or duplicate close events
//   - the caller's limit is respected, bad arguments are harmless
// No driver is opened and nothing leaves the machine.
#include "pb_internal.h"
#include "pbtest.h"
#include <stddef.h>
#include "../gui/api/pb_api.h"

/* The app mirrors the engine's flow record (PBFlow in pb_api.h = PB_FLOW in ProxyBridge.h): when the engine DLL is
   loaded directly the two must be byte for byte the same. */
typedef char flow_size_matches[sizeof(PBFlow) == sizeof(PB_FLOW) ? 1 : -1];
typedef char flow_fields_match[(offsetof(PBFlow, id) == offsetof(PB_FLOW, id) && offsetof(PBFlow, pid) == offsetof(PB_FLOW, pid) &&
    offsetof(PBFlow, proxy_config_id) == offsetof(PB_FLOW, proxy_config_id) && offsetof(PBFlow, rule_id) == offsetof(PB_FLOW, rule_id) && offsetof(PBFlow, age_ms) == offsetof(PB_FLOW, age_ms) &&
    offsetof(PBFlow, sent) == offsetof(PB_FLOW, sent) && offsetof(PBFlow, received) == offsetof(PB_FLOW, received) &&
    offsetof(PBFlow, port) == offsetof(PB_FLOW, port) && offsetof(PBFlow, is_udp) == offsetof(PB_FLOW, is_udp) &&
    offsetof(PBFlow, is_ipv6) == offsetof(PB_FLOW, is_ipv6) && offsetof(PBFlow, dest) == offsetof(PB_FLOW, dest) &&
    offsetof(PBFlow, name) == offsetof(PB_FLOW, name) && offsetof(PBFlow, host) == offsetof(PB_FLOW, host) &&
    PB_FLOWS_MAX_GUI == PB_FLOWS_MAX) ? 1 : -1];

static BOOL make_pair(SOCKET* a, SOCKET* b)
{
    SOCKET ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa; int len = sizeof(sa);
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr*)&sa, sizeof(sa)) || listen(ls, 1) || getsockname(ls, (struct sockaddr*)&sa, &len)) { closesocket(ls); return FALSE; }
    *a = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(*a, (struct sockaddr*)&sa, sizeof(sa))) { closesocket(ls); closesocket(*a); return FALSE; }
    *b = accept(ls, NULL, NULL);
    closesocket(ls);
    DWORD timeout = 4000;
    setsockopt(*a, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(*a, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(*b, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(*b, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    return *b != INVALID_SOCKET;
}

static BOOL send_n(SOCKET s, int n) { char buf[4096]; memset(buf, 'x', sizeof buf); while (n > 0) { int c = n > (int)sizeof buf ? (int)sizeof buf : n; int r = send(s, buf, c, 0); if (r <= 0) return FALSE; n -= r; } return TRUE; }
static BOOL recv_n_bytes(SOCKET s, int n) { char buf[4096]; while (n > 0) { int r = recv(s, buf, n > (int)sizeof buf ? (int)sizeof buf : n, 0); if (r <= 0) return FALSE; n -= r; } return TRUE; }

// polls the engine until `pred` holds or ~4 s pass
static PB_FLOW g_f[PB_FLOWS_MAX];
static volatile LONG snapshot_closed;
static volatile LONG half_closed, half_failed;
static void capture_snapshot(const char *proc, DWORD pid, const char *ip, UINT16 port, const char *info)
{
    (void)proc; (void)pid; (void)ip; (void)port;
    if (strstr(info, "status=CLOSED") && strstr(info, "rule=R17 Original browser") && strstr(info, "match=APP:C:\\Apps\\*"))
        InterlockedIncrement(&snapshot_closed);
    if (strstr(info, "rule=R100 Half-close")) {
        if (strstr(info, "status=CLOSED")) InterlockedIncrement(&half_closed);
        if (strstr(info, "IOCP relay failed")) InterlockedIncrement(&half_failed);
    }
}
static UINT32  g_n;
static BOOL wait_flows(UINT32 want, UINT64 sent, UINT64 recv)
{
    for (int i = 0; i < 400; i++)
    {
        g_n = ProxyBridge_GetFlows(g_f, PB_FLOWS_MAX);
        if (g_n == want && (want == 0 || (g_f[0].sent == sent && g_f[0].received == recv))) return TRUE;
        Sleep(10);
    }
    return FALSE;
}

static void wait_drained(void)
{
    CHECK(wait_flows(0, 0, 0));
    for (int i = 0; i < 400 && g_active_relays > 0; i++) Sleep(10);
    CHECK(g_active_relays == 0);
}

static FLOW_META half_meta(void)
{
    FLOW_META m = {0}; m.pid = GetCurrentProcessId(); m.port = 443;
    m.log_context.rule_id = 100;
    strcpy_s(m.log_context.rule_name, sizeof(m.log_context.rule_name), "Half-close");
    return m;
}

/* Patterned, multi-buffer payload: verify content and order, not just byte counts. */
static BOOL pattern_io(SOCKET s, int count, BOOL sending)
{
    unsigned char buf[4096]; int offset = 0;
    while (offset < count) {
        int n = count - offset; if (n > (int)sizeof(buf)) n = sizeof(buf);
        if (sending) for (int i = 0; i < n; i++) buf[i] = (unsigned char)((offset + i) * 31 + 7);
        int done = sending ? send(s, (char*)buf, n, 0) : recv(s, (char*)buf, n, 0);
        if (done <= 0) return FALSE;
        if (!sending) for (int i = 0; i < done; i++)
            if (buf[i] != (unsigned char)((offset + i) * 31 + 7)) return FALSE;
        offset += done;
    }
    return TRUE;
}

typedef struct { SOCKET socket; int count; } SendJob;
static DWORD WINAPI send_and_fin(LPVOID arg)
{
    SendJob *job = (SendJob*)arg;
    return pattern_io(job->socket, job->count, TRUE) && shutdown(job->socket, SD_SEND) == 0 ? 0 : 1;
}

/* Both orientations matter: app FIN before a delayed response, and proxy FIN while
   the app still has a large upload. The other receive must remain alive in both. */
static void test_half_close(BOOL app_first)
{
    SOCKET app, rc, rp, proxy; char byte;
    BOOL paired = make_pair(&app, &rc) && make_pair(&rp, &proxy);
    CHECK(paired); if (!paired) return;
    FLOW_META m = half_meta();
    LONG closed_before = half_closed, failed_before = half_failed;
    CHECK(relay_start(rc, rp, &m));
    SOCKET first = app_first ? app : proxy, other = app_first ? proxy : app;
    CHECK(pattern_io(first, 4097, TRUE));
    CHECK(shutdown(first, SD_SEND) == 0);
    CHECK(pattern_io(other, 4097, FALSE));
    CHECK(recv(other, &byte, 1, 0) == 0);  /* FIN arrives after all preceding bytes */
    CHECK(wait_flows(1, app_first ? 4097 : 0, app_first ? 0 : 4097));
    CHECK(half_closed == closed_before);  /* half-close is not a terminal event */
    Sleep(50);                           /* response is deliberately not ready at FIN */
    SendJob job = {other, 524325};
    HANDLE sender = CreateThread(NULL, 0, send_and_fin, &job, 0, NULL);
    CHECK(sender != NULL);
    if (sender) {
        CHECK(pattern_io(first, job.count, FALSE));
        CHECK(recv(first, &byte, 1, 0) == 0);
        DWORD result = 1;
        DWORD waited = WaitForSingleObject(sender, 10000);
        CHECK(waited == WAIT_OBJECT_0);
        if (waited != WAIT_OBJECT_0) ExitProcess(2); /* never leave a thread using stack storage */
        CHECK(GetExitCodeThread(sender, &result) && result == 0);
        CloseHandle(sender);
    }
    closesocket(app); closesocket(proxy);
    wait_drained();
    CHECK(half_closed == closed_before + 1);
    CHECK(half_failed == failed_before);
}

static void test_half_close_abort(BOOL stop_pool)
{
    SOCKET app, rc, rp, proxy; char byte;
    BOOL paired = make_pair(&app, &rc) && make_pair(&rp, &proxy);
    CHECK(paired); if (!paired) return;
    FLOW_META m = half_meta(); LONG closed_before = half_closed, failed_before = half_failed;
    CHECK(relay_start(rc, rp, &m));
    CHECK(shutdown(app, SD_SEND) == 0);
    CHECK(recv(proxy, &byte, 1, 0) == 0);
    CHECK(wait_flows(1, 0, 0));
    if (stop_pool) {
        relay_pool_stop();
        CHECK(recv(app, &byte, 1, 0) <= 0);
    } else {
        struct linger abortive = {1, 0};
        CHECK(setsockopt(proxy, SOL_SOCKET, SO_LINGER, (char*)&abortive, sizeof(abortive)) == 0);
        closesocket(proxy); proxy = INVALID_SOCKET;
        CHECK(recv(app, &byte, 1, 0) <= 0);
    }
    wait_drained();
    CHECK(half_closed == closed_before + (stop_pool ? 1 : 0));
    CHECK(half_failed == failed_before + (stop_pool ? 0 : 1)); /* IOCP may report a Win32 or WSA error */
    closesocket(app); if (proxy != INVALID_SOCKET) closesocket(proxy);
    if (stop_pool) CHECK(relay_pool_start());
}

static void test_simultaneous_fin(void)
{
    LONG closed_before = half_closed, failed_before = half_failed;
    for (int i = 0; i < 32; i++) {
        SOCKET app, rc, rp, proxy; char byte;
        BOOL paired = make_pair(&app, &rc) && make_pair(&rp, &proxy);
        CHECK(paired); if (!paired) return;
        FLOW_META m = half_meta();
        CHECK(relay_start(rc, rp, &m));
        CHECK(shutdown(app, SD_SEND) == 0);
        CHECK(shutdown(proxy, SD_SEND) == 0);
        CHECK(recv(app, &byte, 1, 0) == 0);
        CHECK(recv(proxy, &byte, 1, 0) == 0);
        closesocket(app); closesocket(proxy);
    }
    wait_drained();
    CHECK(half_closed == closed_before + 32); /* exactly once, despite racing workers */
    CHECK(half_failed == failed_before);
}

int main(void)
{
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    running = TRUE;                                              /* relay_start() refuses to work on a stopped engine */
    ProxyBridge_SetConnectionCallback(capture_snapshot);
    ProxyBridge_SetTrafficLoggingEnabled(TRUE);
    CHECK(relay_pool_start());

    CHECK(ProxyBridge_GetFlows(NULL, 10) == 0);                  /* bad arguments are harmless */
    { PB_FLOW one; CHECK(ProxyBridge_GetFlows(&one, 0) == 0); }
    CHECK(wait_flows(0, 0, 0));

    /* app <-> [relay] <-> proxy, as two loopback pairs */
    SOCKET app, relayClient, relayProxy, proxy;
    CHECK(make_pair(&app, &relayClient) && make_pair(&relayProxy, &proxy));
    FLOW_META m; ZeroMemory(&m, sizeof m);
    m.pid = GetCurrentProcessId(); m.proxy_id = 9; m.rule_id = 17; m.port = 443; m.v6 = FALSE;
    m.log_context.rule_id = 17;
    strcpy_s(m.log_context.rule_name, sizeof(m.log_context.rule_name), "Original browser");
    strcpy_s(m.log_context.match, sizeof(m.log_context.match), "APP:C:\\Apps\\*");
    UINT32 dest = 0x08080808u; memcpy(m.dest, &dest, 4);        /* 8.8.8.8 */
    CHECK(relay_start(relayClient, relayProxy, &m));
    strcpy_s(m.log_context.rule_name, sizeof(m.log_context.rule_name), "Edited after connect");

    CHECK(wait_flows(1, 0, 0));
    CHECK(g_n == 1 && g_f[0].pid == m.pid && g_f[0].proxy_config_id == 9 && g_f[0].rule_id == 17 && g_f[0].port == 443 && !g_f[0].is_udp && !g_f[0].is_ipv6);
    CHECK(strlen(g_f[0].name) > 0 && _stricmp(g_f[0].name, "test_flows.exe") == 0);        /* the process name, not the path */
    CHECK(!strcmp(g_f[0].host, "8.8.8.8"));                                                /* no domain known: the address */
    CHECK(g_f[0].age_ms != 0xFFFFFFFFu && g_f[0].id != 0);
    UINT64 id = g_f[0].id;

    /* bytes are forwarded and counted per direction */
    CHECK(send_n(app, 1000) && recv_n_bytes(proxy, 1000));
    CHECK(send_n(proxy, 250000) && recv_n_bytes(app, 250000));       /* more than one read, so the counter must add up */
    CHECK(wait_flows(1, 1000, 250000));
    CHECK(g_f[0].id == id && g_f[0].sent == 1000 && g_f[0].received == 250000);

    /* a second connection (IPv6 label) is listed newest first; the first one keeps its identity */
    SOCKET app2, rc2, rp2, px2;
    CHECK(make_pair(&app2, &rc2) && make_pair(&rp2, &px2));
    FLOW_META m2; ZeroMemory(&m2, sizeof m2); m2.pid = GetCurrentProcessId(); m2.proxy_id = 3; m2.port = 80; m2.v6 = TRUE; m2.dest[15] = 1;   /* ::1 */
    CHECK(relay_start(rc2, rp2, &m2));
    CHECK(wait_flows(2, 0, 0) || g_n == 2);
    CHECK(g_n == 2 && g_f[0].id != id && g_f[0].is_ipv6 && !strcmp(g_f[0].host, "::1") && g_f[1].id == id && g_f[1].sent == 1000);
    { PB_FLOW lim[1]; CHECK(ProxyBridge_GetFlows(lim, 1) == 1); }                          /* the caller's limit is respected */

    /* app FIN propagates, but reverse traffic remains possible until proxy FIN */
    closesocket(app);
    char c; CHECK(recv(proxy, &c, 1, 0) <= 0);                                              /* the proxy side saw the close too */
    closesocket(proxy);
    CHECK(wait_flows(1, 0, 0));
    CHECK(g_n == 1 && g_f[0].id != id);

    closesocket(app2);
    CHECK(recv(px2, &c, 1, 0) == 0);
    closesocket(px2);
    CHECK(wait_flows(0, 0, 0));
    for (int i = 0; i < 300 && g_active_relays > 0; i++) Sleep(10);
    CHECK(g_active_relays == 0);                                                            /* nothing leaked */
    CHECK(snapshot_closed == 1);  /* IOCP close event retains the decision-time rule snapshot */

    test_half_close(TRUE);
    test_half_close(FALSE);
    test_half_close_abort(FALSE);
    test_half_close_abort(TRUE);
    test_simultaneous_fin();

    relay_pool_stop();
    CHECK(relay_flows_snapshot(g_f, PB_FLOWS_MAX) == 0);
    running = FALSE;
    WSACleanup();
    return pbtest_done("test_flows");
}
