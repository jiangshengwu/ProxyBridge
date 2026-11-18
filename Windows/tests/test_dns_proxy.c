// Real UDP/TCP loopback resolvers and SOCKS5/HTTP proxies. No driver, public
// network, OS DNS settings or real user profile is touched by these regressions.
#include "pb_internal.h"
#include "pbtest.h"

static UINT16 u16(const UINT8 *p) { return (UINT16)((p[0] << 8) | p[1]); }
static void p16(UINT8 *p, int n) { p[0] = (UINT8)(n >> 8); p[1] = (UINT8)n; }
static int query_for(UINT8 *q, const char *name, int type)
{
    memset(q, 0, 12); p16(q, 0x4217); q[2] = 1; q[5] = 1; int n = 12;
    while (*name) {
        const char *dot = strchr(name, '.'); int len = dot ? (int)(dot - name) : (int)strlen(name);
        q[n++] = (UINT8)len; memcpy(q + n, name, len); n += len;
        if (!dot) break; name = dot + 1;
    }
    q[n++] = 0; p16(q + n, type); p16(q + n + 2, 1); return n + 4;
}
static int answer_for(const UINT8 *q, int len, UINT8 *a, int mode)
{
    PB_DNS_QUESTION question;
    if (!dns_question(q, len, &question)) return 0;
    int n = question.end; memcpy(a, q, n); a[2] = 0x81; a[3] = (UINT8)(0x80 | (mode <= 5 ? mode : 0));
    memset(a + 6, 0, 6);
    if (mode == 7) { a[2] |= 2; return n; }
    if (mode == 8 || (mode > 0 && mode <= 5)) return n;
    a[7] = 1; a[n++] = 0xc0; a[n++] = 0x0c;
    p16(a + n, question.type); p16(a + n + 2, 1); n += 4;
    memset(a + n, 0, 4); a[n + 3] = 60; n += 4;
    if (question.type == 28) {
        p16(a + n, 16); n += 2; memset(a + n, 0, 16); a[n] = 0x26; a[n + 1] = 6; a[n + 15] = 7; n += 16;
    } else { p16(a + n, 4); n += 2; a[n++] = 203; a[n++] = 0; a[n++] = 113; a[n++] = 7; }
    if (mode == 6) a[1] ^= 1; // wrong transaction, must never be learned/returned
    return n;
}
static BOOL rx(SOCKET s, UINT8 *p, int n) { return recv_n(s, (char*)p, n) == n; }
static BOOL tx(SOCKET s, const UINT8 *p, int n) { return send_all(s, (const char*)p, n) == n; }

typedef struct {
    SOCKET listener; HANDLE thread; struct sockaddr_in addr;
    BOOL udp, proxy, http, auth, fragment, reject_first, reject_all, stall;
    int mode;
    volatile LONG stop, calls, dns_queries;
    UINT32 targets[4];
    BOOL auth_seen, http_auth_seen;
} Fake;

static DWORD WINAPI serve(LPVOID arg)
{
    Fake *f = (Fake*)arg;
    while (!f->stop) {
        fd_set reads; FD_ZERO(&reads); FD_SET(f->listener, &reads); struct timeval tv = {0, 50000};
        if (select(0, &reads, NULL, NULL, &tv) <= 0) continue;
        UINT8 q[PB_DNS_MAX], a[PB_DNS_MAX]; int len = 0;
        if (f->udp) {
            struct sockaddr_in peer; int plen = sizeof(peer);
            len = recvfrom(f->listener, (char*)q, sizeof(q), 0, (struct sockaddr*)&peer, &plen);
            InterlockedIncrement(&f->calls);
            if (len > 0 && f->mode != 9) { int n = answer_for(q, len, a, f->mode); sendto(f->listener, (char*)a, n, 0, (struct sockaddr*)&peer, plen); }
            continue;
        }
        SOCKET s = accept(f->listener, NULL, NULL); if (s == INVALID_SOCKET) continue;
        DWORD timeout = 2500; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        LONG call = InterlockedIncrement(&f->calls);
        BOOL ok = TRUE;
        if (f->proxy && f->http) {
            char header[4096]; int n = 0;
            while (n < (int)sizeof(header) - 1) { if (recv(s, header + n, 1, 0) != 1) { ok = FALSE; break; } n++; if (n >= 4 && !memcmp(header + n - 4, "\r\n\r\n", 4)) break; }
            header[n] = 0;
            f->http_auth_seen = strstr(header, "Proxy-Authorization: Basic YWxpY2U6c2VjcmV0") != NULL;
            ok = ok && strstr(header, ":53 HTTP/1.1") != NULL;
            const char *response = f->reject_all ? "HTTP/1.1 407 Authentication required\r\n\r\n" : "HTTP/1.1 200 Connection established\r\nX-Test: dns\r\n\r\n";
            tx(s, (const UINT8*)response, (int)strlen(response));
            if (f->reject_all) ok = FALSE;
        } else if (f->proxy) {
            UINT8 b[1100];
            ok = rx(s, b, 2);
            if (ok) { int count = b[1]; ok = count <= 10 && rx(s, b + 2, count); }
            UINT8 method[2] = {5, f->auth ? 2 : 0};
            if (ok) ok = tx(s, method, 2);
            if (ok && f->auth) {
                ok = rx(s, b, 2); int user = b[1];
                if (ok) ok = rx(s, b + 2, user + 1);
                int pass = ok ? b[2 + user] : 0;
                if (ok) ok = rx(s, b + 3 + user, pass);
                f->auth_seen = ok && user == 5 && pass == 6 && !memcmp(b + 2, "alice", 5) && !memcmp(b + 3 + user, "secret", 6);
                UINT8 reply[2] = {1, f->auth_seen ? 0 : 1};
                ok = ok && tx(s, reply, 2) && f->auth_seen;
            }
            if (ok) ok = rx(s, b, 10) && b[0] == 5 && b[1] == 1 && b[3] == 1 && b[8] == 0 && b[9] == 53;
            if (ok && call <= 4) memcpy(&f->targets[call - 1], b + 4, 4);
            BOOL rejected = f->reject_all || (f->reject_first && call == 1);
            UINT8 response[10] = {5, rejected ? 5 : 0, 0, 1, 0,0,0,0,0,0};
            if (ok) ok = tx(s, response, 10) && !rejected;
        }
        if (ok) {
            UINT8 prefix[2];
            ok = rx(s, prefix, 2); if (ok) len = u16(prefix);
            ok = ok && len >= 17 && len <= PB_DNS_MAX && rx(s, q, len);
            if (ok) {
                InterlockedIncrement(&f->dns_queries);
                if (f->stall) { UINT8 byte; recv(s, (char*)&byte, 1, 0); }
                else if (f->mode != 9) {
                    int n = answer_for(q, len, a, f->mode); p16(prefix, n); tx(s, prefix, 2);
                    if (f->fragment) for (int i = 0; i < n; i++) { if (!tx(s, a + i, 1)) break; Sleep(1); }
                    else tx(s, a, n);
                }
            }
        }
        closesocket(s);
    }
    return 0;
}

static void start_fake(Fake *f, BOOL udp, BOOL proxy)
{
    ZeroMemory(f, sizeof(*f)); f->udp = udp; f->proxy = proxy;
    f->listener = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    f->addr.sin_family = AF_INET; f->addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(f->listener, (struct sockaddr*)&f->addr, sizeof(f->addr)) == 0);
    int n = sizeof(f->addr); getsockname(f->listener, (struct sockaddr*)&f->addr, &n);
    if (!udp) CHECK(listen(f->listener, 8) == 0);
    f->thread = CreateThread(NULL, 0, serve, f, 0, NULL); CHECK(f->thread != NULL);
}
static void stop_fake(Fake *f)
{
    InterlockedExchange(&f->stop, 1);
    DWORD waited = WaitForSingleObject(f->thread, 4000); CHECK(waited == WAIT_OBJECT_0);
    if (waited != WAIT_OBJECT_0) ExitProcess(2);
    CloseHandle(f->thread); closesocket(f->listener);
}
static PROXY_CONFIG proxy_config(Fake *f)
{
    PROXY_CONFIG p = {0}; p.config_id = 1; p.type = f->http ? PROXY_TYPE_HTTP : PROXY_TYPE_SOCKS5;
    strcpy_s(p.host, sizeof(p.host), "127.0.0.1"); p.resolved_ip = htonl(INADDR_LOOPBACK); p.port = ntohs(f->addr.sin_port);
    if (f->auth) { strcpy_s(p.username, sizeof(p.username), "alice"); strcpy_s(p.password, sizeof(p.password), "secret"); }
    return p;
}

static void test_policy(void)
{
    UINT32 id = 0;
    g_proxy_config_count = 2;
    for (int i = 0; i < 2; i++) { g_proxy_configs[i].config_id = i + 1; strcpy_s(g_proxy_configs[i].host, 256, "127.0.0.1"); g_proxy_configs[i].resolved_ip = htonl(INADDR_LOOPBACK); g_proxy_configs[i].port = 1080 + i; }
    UINT32 local = ProxyBridge_AddRule("*", "192.168.*.*;10.*.*.*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE);
    UINT32 direct = ProxyBridge_AddRule("direct.exe", "*", "*", "*", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE);
    UINT32 private_domain = ProxyBridge_AddRule("*", "*", "*", "private.example.org", RULE_PROTOCOL_BOTH, RULE_ACTION_DIRECT, 0, FALSE);
    UINT32 proxy = ProxyBridge_AddRule("ChatGPT*", "*", "443", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 2, FALSE);
    CHECK(dns_proxy_policy("ChatGPT.exe", FALSE, "chatgpt.com", &id) && id == 2);
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "private.example.org", &id));
    CHECK(!dns_proxy_policy("svchost.exe", TRUE, "private.example.org", &id));
    CHECK(!dns_proxy_policy("direct.exe", FALSE, "chatgpt.com", &id));
    CHECK(!dns_proxy_policy("other.exe", FALSE, "chatgpt.com", &id));
    CHECK(dns_proxy_policy("svchost.exe", TRUE, "chatgpt.com", &id) && id == 2);
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "nas.local", &id));
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "router", &id));
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "1.50.168.192.in-addr.arpa", &id));
    CHECK(dns_proxy_policy("ChatGPT.exe", FALSE, NULL, &id)); /* TCP before question arrives */
    ProxyBridge_DisableRule(proxy); CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "chatgpt.com", &id));
    ProxyBridge_EnableRule(proxy); ProxyBridge_SetEnabled(FALSE); CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "chatgpt.com", &id)); ProxyBridge_SetEnabled(TRUE);
    ProxyBridge_DeleteRule(proxy);
    proxy = ProxyBridge_AddRule("ChatGPT*", "*", "*", "chatgpt.com", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 1, FALSE);
    CHECK(dns_proxy_policy("ChatGPT.exe", FALSE, "chatgpt.com", &id) && id == 1);
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "unrelated.org", &id));
    CHECK(dns_proxy_policy("ChatGPT.exe", FALSE, NULL, &id));
    ProxyBridge_DeleteRule(proxy);
    proxy = ProxyBridge_AddRule("ChatGPT*", "*", "*", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 99, FALSE);
    CHECK(!dns_proxy_policy("ChatGPT.exe", FALSE, "chatgpt.com", &id)); /* no unintended fallback to another proxy */
    ProxyBridge_DeleteRule(proxy); ProxyBridge_DeleteRule(private_domain); ProxyBridge_DeleteRule(direct); ProxyBridge_DeleteRule(local);
    CHECK(dns_local_name("a.home") && dns_local_name("a.lan") && dns_local_name("a.internal") && !dns_local_name("chatgpt.com"));
}

static void test_transport(void)
{
    UINT8 q[512], a[PB_DNS_MAX]; int qlen = query_for(q, "chatgpt.com", 1);
    Fake local, proxy; start_fake(&local, TRUE, FALSE); start_fake(&proxy, FALSE, TRUE);
    PROXY_CONFIG config = proxy_config(&proxy);
    CHECK(dns_proxy_start());
    int n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && dns_response_valid(q, qlen, a, n)); CHECK(proxy.calls == 0);
    local.mode = 3; n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n == qlen && (a[3] & 15) == 3 && proxy.calls == 0); /* NXDOMAIN authoritative */
    local.mode = 8; n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n == qlen && !dns_response_retry(a, n) && proxy.calls == 0); /* NODATA */
    local.mode = 2; proxy.fragment = TRUE;
    n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 1 && !memcmp(&proxy.targets[0], "\x01\x01\x01\x01", 4));
    char domain[256]; CHECK(dns_cache_lookup(parse_ipv4("203.0.113.7"), domain, sizeof(domain)) && !strcmp(domain, "chatgpt.com"));
    local.mode = 9; n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 2); /* local timeout */
    local.mode = 6; n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 3); /* wrong ID discarded */
    local.mode = 7; n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 4); /* TC retried over remote TCP */
    local.mode = 5;
    n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 5); /* REFUSED */
    local.mode = 2; qlen = query_for(q, "printer.local", 1); LONG before = proxy.calls;
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config) == 0 && proxy.calls == before);
    qlen = query_for(q, "ipv6.example.org", 28);
    n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    UINT8 ip6[16] = {0x26,6}; ip6[15] = 7;
    CHECK(n > qlen && dns_cache_lookup_v6(ip6, domain, sizeof(domain)) && !strcmp(domain, "ipv6.example.org"));
    stop_fake(&proxy);
    start_fake(&proxy, FALSE, TRUE); proxy.reject_first = TRUE; config = proxy_config(&proxy);
    n = dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config);
    CHECK(n > qlen && proxy.calls == 2 && !memcmp(&proxy.targets[1], "\x09\x09\x09\x09", 4));
    stop_fake(&proxy);
    start_fake(&proxy, FALSE, TRUE); proxy.auth = TRUE; config = proxy_config(&proxy);
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config) > qlen && proxy.auth_seen);
    stop_fake(&proxy);
    start_fake(&proxy, FALSE, TRUE); proxy.http = TRUE; proxy.auth = TRUE; config = proxy_config(&proxy);
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config) > qlen && proxy.http_auth_seen);
    proxy.reject_all = TRUE;
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), FALSE, &config) == 0);
    stop_fake(&proxy); stop_fake(&local);
    start_fake(&local, FALSE, FALSE); start_fake(&proxy, FALSE, TRUE); config = proxy_config(&proxy); local.mode = 2;
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), TRUE, &config) > qlen && proxy.calls == 1);
    local.mode = 0; before = proxy.calls;
    CHECK(dns_proxy_exchange(q, qlen, a, sizeof(a), (struct sockaddr*)&local.addr, sizeof(local.addr), TRUE, &config) > qlen && proxy.calls == before);
    stop_fake(&proxy); stop_fake(&local); dns_proxy_stop();
}

typedef struct { Fake *local; PROXY_CONFIG proxy; int result; } ExchangeJob;
static DWORD WINAPI stalled_exchange(LPVOID arg)
{
    ExchangeJob *job = (ExchangeJob*)arg; UINT8 q[512], a[PB_DNS_MAX];
    int len = query_for(q, "pending.example.org", 1);
    job->result = dns_proxy_exchange(q, len, a, sizeof(a), (struct sockaddr*)&job->local->addr, sizeof(job->local->addr), FALSE, &job->proxy);
    return 0;
}

static void test_cancel_upstream(void)
{
    Fake local, proxy; start_fake(&local, TRUE, FALSE); local.mode = 2;
    start_fake(&proxy, FALSE, TRUE); proxy.stall = TRUE;
    CHECK(dns_proxy_start());
    ExchangeJob job = {&local, proxy_config(&proxy), -1};
    HANDLE thread = CreateThread(NULL, 0, stalled_exchange, &job, 0, NULL); CHECK(thread != NULL);
    for (int i = 0; i < 200 && proxy.dns_queries == 0; i++) Sleep(5);
    CHECK(proxy.dns_queries == 1);
    ULONGLONG start = GetTickCount64(); dns_proxy_stop();
    DWORD waited = WaitForSingleObject(thread, 2000);
    CHECK(waited == WAIT_OBJECT_0 && GetTickCount64() - start < 2000);
    if (waited != WAIT_OBJECT_0) ExitProcess(2);
    CHECK(job.result == 0); CloseHandle(thread);
    stop_fake(&proxy); stop_fake(&local);
}

typedef struct { SOCKET socket; BOOL tcp; } Fake6;
static DWORD WINAPI serve6(LPVOID arg)
{
    Fake6 *f = (Fake6*)arg; UINT8 q[512], answer[1024], prefix[2];
    SOCKET s = f->tcp ? accept(f->socket, NULL, NULL) : f->socket;
    if (s == INVALID_SOCKET) return 1;
    DWORD timeout = 2000; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    struct sockaddr_in6 peer; int plen = sizeof(peer), n = 0;
    if (f->tcp) { if (rx(s, prefix, 2)) { n = u16(prefix); if (n > (int)sizeof(q) || !rx(s, q, n)) n = 0; } }
    else n = recvfrom(s, (char*)q, sizeof(q), 0, (struct sockaddr*)&peer, &plen);
    if (n > 0) {
        int count = answer_for(q, n, answer, 0);
        if (f->tcp) { p16(prefix, count); tx(s, prefix, 2); tx(s, answer, count); }
        else sendto(s, (char*)answer, count, 0, (struct sockaddr*)&peer, plen);
    }
    if (f->tcp) closesocket(s);
    return n > 0 ? 0 : 1;
}

static void test_ipv6_resolver(void)
{
    CHECK(dns_proxy_start());
    for (int tcp = 0; tcp < 2; tcp++) {
        Fake6 f = {socket(AF_INET6, tcp ? SOCK_STREAM : SOCK_DGRAM, 0), tcp};
        struct sockaddr_in6 addr = {0}; addr.sin6_family = AF_INET6; addr.sin6_addr = in6addr_loopback;
        CHECK(bind(f.socket, (struct sockaddr*)&addr, sizeof(addr)) == 0);
        int size = sizeof(addr); getsockname(f.socket, (struct sockaddr*)&addr, &size);
        if (tcp) CHECK(listen(f.socket, 1) == 0);
        HANDLE thread = CreateThread(NULL, 0, serve6, &f, 0, NULL); CHECK(thread != NULL);
        UINT8 q[512], answer[1024]; int n = query_for(q, "ipv6-resolver.example.org", 28);
        int count = dns_proxy_exchange(q, n, answer, sizeof(answer), (struct sockaddr*)&addr, sizeof(addr), tcp, NULL);
        CHECK(count > n && dns_response_valid(q, n, answer, count));
        DWORD waited = WaitForSingleObject(thread, 3000), result = 1; CHECK(waited == WAIT_OBJECT_0);
        if (waited != WAIT_OBJECT_0) ExitProcess(2);
        CHECK(GetExitCodeThread(thread, &result) && result == 0);
        CloseHandle(thread); closesocket(f.socket);
    }
    dns_proxy_stop();
}

static void test_wire(void)
{
    UINT8 q[512], a[PB_DNS_MAX], packet[PB_DNS_MAX], reply[PB_DNS_MAX];
    int qlen = query_for(q, "chatgpt.com", 1), alen = answer_for(q, qlen, a, 0); PB_DNS_QUESTION parsed;
    CHECK(dns_question(q, qlen, &parsed) && parsed.type == 1 && !strcmp(parsed.name, "chatgpt.com"));
    CHECK(dns_response_valid(q, qlen, a, alen));
    a[1] ^= 1; CHECK(!dns_response_valid(q, qlen, a, alen)); a[1] ^= 1;
    a[13] ^= 1; CHECK(!dns_response_valid(q, qlen, a, alen)); a[13] ^= 1;
    CHECK(!dns_response_valid(q, qlen, a, alen - 1));
    for (int v6 = 0; v6 < 2; v6++) {
        memset(packet, 0, sizeof(packet)); int iplen = v6 ? 40 : 20;
        PWINDIVERT_UDPHDR udp = (PWINDIVERT_UDPHDR)(packet + iplen);
        udp->SrcPort = htons(54321); udp->DstPort = htons(53); udp->Length = htons(8 + qlen);
        memcpy(packet + iplen + 8, q, qlen);
        if (v6) {
            PWINDIVERT_IPV6HDR ip = (PWINDIVERT_IPV6HDR)packet; ip->Version = 6; ip->NextHdr = 17; ip->Length = htons(8 + qlen); ip->HopLimit = 64;
            ((UINT8*)ip->SrcAddr)[0] = 0x26; ((UINT8*)ip->DstAddr)[0] = 0x20;
        } else {
            PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)packet; ip->Version = 4; ip->HdrLength = 5; ip->Protocol = 17; ip->Length = htons(iplen + 8 + qlen); ip->TTL = 64;
            ip->SrcAddr = parse_ipv4("192.168.50.198"); ip->DstAddr = parse_ipv4("192.168.50.1");
        }
        WINDIVERT_ADDRESS addr = {0}; addr.Outbound = TRUE;
        int n = dns_proxy_make_reply(packet, iplen + 8 + qlen, a, alen, reply, sizeof(reply), &addr);
        CHECK(n == iplen + 8 + alen && !addr.Outbound);
        PWINDIVERT_UDPHDR r = (PWINDIVERT_UDPHDR)(reply + iplen);
        CHECK(r->SrcPort == htons(53) && r->DstPort == htons(54321) && r->Checksum != 0);
        CHECK(!memcmp(reply + iplen + 8, a, alen));
        if (!v6) CHECK(((PWINDIVERT_IPHDR)reply)->SrcAddr == parse_ipv4("192.168.50.1"));
        else CHECK(((UINT8*)((PWINDIVERT_IPV6HDR)reply)->SrcAddr)[0] == 0x20);
        CHECK(dns_proxy_make_reply(packet, iplen + 8 + qlen, a, alen, reply, 10, &addr) == 0);
        // A large valid answer produces TC + the original question, not fragmented UDP.
        UINT8 large[1024]; memcpy(large, a, alen); p16(large + 10, 1); int pos = alen;
        large[pos++] = 0; p16(large + pos, 41); pos += 2; p16(large + pos, 1232); pos += 2; memset(large + pos, 0, 4); pos += 4;
        p16(large + pos, 600); pos += 2; memset(large + pos, 0, 600); pos += 600;
        CHECK(dns_response_valid(q, qlen, large, pos));
        n = dns_proxy_make_reply(packet, iplen + 8 + qlen, large, pos, reply, sizeof(reply), &addr);
        CHECK(n == iplen + 8 + qlen && (reply[iplen + 10] & 2) && u16(reply + iplen + 14) == 0);
    }
    // Question/answer parsing at every guarded prefix, plus random hostile inputs.
    for (int cut = 0; cut <= alen; cut++) { void *base; UINT8 *g = pb_guarded(a, cut, &base); dns_question(g, cut, &parsed); dns_response_valid(q, qlen, g, cut); pb_guard_release(base); }
    srand(147);
    for (int i = 0; i < 12000; i++) {
        UINT8 bytes[256]; int n = rand() % sizeof(bytes); for (int j = 0; j < n; j++) bytes[j] = (UINT8)rand();
        void *base; UINT8 *g = pb_guarded(bytes, n, &base); dns_question(g, n, &parsed); dns_response_valid(q, qlen, g, n); pb_guard_release(base);
    }
    CHECK(TRUE);
}

typedef struct { SOCKET client; CONNECTION_CONFIG config; } Client;
static DWORD WINAPI tcp_client(LPVOID arg) { dns_proxy_tcp_client(&((Client*)arg)->config); return 0; }
static void test_tcp_session(void)
{
    Fake local, proxy; start_fake(&local, FALSE, FALSE); local.mode = 2;
    start_fake(&proxy, FALSE, TRUE); g_proxy_config_count = 1; g_proxy_configs[0] = proxy_config(&proxy);
    UINT32 rule = ProxyBridge_AddRule("test_dns_proxy.exe", "*", "*", "*", RULE_PROTOCOL_TCP, RULE_ACTION_PROXY, 1, FALSE);
    CHECK(dns_proxy_start());
    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0); struct sockaddr_in sa = {0}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(bind(listener, (struct sockaddr*)&sa, sizeof(sa)) == 0 && listen(listener, 1) == 0);
    int size = sizeof(sa); getsockname(listener, (struct sockaddr*)&sa, &size);
    Client c = {0}; c.client = socket(AF_INET, SOCK_STREAM, 0); CHECK(connect(c.client, (struct sockaddr*)&sa, size) == 0);
    c.config.client_socket = accept(listener, NULL, NULL); c.config.pid = GetCurrentProcessId();
    c.config.orig_dest_ip = htonl(INADDR_LOOPBACK); c.config.orig_dest_port = ntohs(local.addr.sin_port);
    HANDLE thread = CreateThread(NULL, 0, tcp_client, &c, 0, NULL);
    UINT8 q[512], a[PB_DNS_MAX], prefix[2];
    for (int i = 0; i < 2; i++) {
        int n = query_for(q, i ? "second.example.org" : "first.example.org", i ? 28 : 1); q[1] = (UINT8)i; p16(prefix, n);
        CHECK(tx(c.client, prefix, 2) && tx(c.client, q, n));
        CHECK(rx(c.client, prefix, 2)); int count = u16(prefix);
        CHECK(count < PB_DNS_MAX && rx(c.client, a, count) && dns_response_valid(q, n, a, count));
    }
    CHECK(proxy.dns_queries == 2);
    ULONGLONG started = GetTickCount64(); dns_proxy_stop();
    DWORD waited = WaitForSingleObject(thread, 2000); CHECK(waited == WAIT_OBJECT_0 && GetTickCount64() - started < 2000);
    if (waited != WAIT_OBJECT_0) ExitProcess(2);
    CloseHandle(thread); closesocket(c.client); closesocket(listener);
    ProxyBridge_DeleteRule(rule); stop_fake(&proxy); stop_fake(&local);
    CHECK(dns_proxy_start()); dns_proxy_stop(); /* repeated lifecycle */
}

int main(void)
{
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); dns_cache_init();
    test_wire(); test_policy(); test_transport(); test_tcp_session(); test_cancel_upstream(); test_ipv6_resolver();
    WSACleanup(); return pbtest_done("test_dns_proxy");
}
