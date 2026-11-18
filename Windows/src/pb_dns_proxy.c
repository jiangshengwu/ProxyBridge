#include "pb_internal.h"

// No system DNS settings are changed. Only eligible app queries and failed queries
// from Dnscache receive fallback. Local/split-DNS successes (including NXDOMAIN)
// stay authoritative; LAN-only names never leave the original resolver.
#define DNS_WORKERS 4
#define DNS_QUEUE 64
#define DNS_LOCAL_MS 400
#define DNS_REMOTE_MS 2200
#define DNS_SOCKETS 192

typedef struct DNS_JOB {
    struct DNS_JOB *next;
    WINDIVERT_ADDRESS addr;
    UINT len;
    PROXY_CONFIG proxy;
    UINT8 packet[1];
} DNS_JOB;
static SRWLOCK dns_job_lock = SRWLOCK_INIT, dns_socket_lock = SRWLOCK_INIT;
static DNS_JOB *dns_head, *dns_tail;
static int dns_queued;
static HANDLE dns_ready, dns_workers[DNS_WORKERS];
static volatile LONG dns_stopping = 1, dns_live;
static volatile LONG dns_eligible_rules, dns_tcp_clients;
static DWORD dns_service_pid;
static struct { SOCKET socket; BOOL used; } dns_sockets[DNS_SOCKETS];

static UINT16 dns_u16(const UINT8 *p) { return (UINT16)((p[0] << 8) | p[1]); }
static void dns_put16(UINT8 *p, int n) { p[0] = (UINT8)(n >> 8); p[1] = (UINT8)n; }

static BOOL dns_config_copy(UINT32 id, PROXY_CONFIG *out)
{
    for (int i = 0; i < g_proxy_config_count; i++) {
        const PROXY_CONFIG *p = &g_proxy_configs[i];
        if ((id ? p->config_id == id : i == 0) && p->host[0] && p->port && p->resolved_ip) {
            *out = *p; return TRUE;
        }
    }
    return FALSE;
}

void dns_proxy_rules_changed(void)
{
    BOOL eligible = FALSE;
    AcquireSRWLockShared(&g_rules_lock);
    for (PROCESS_RULE *r = rules_list; r; r = r->next)
        if (r->enabled && r->action == RULE_ACTION_PROXY) { eligible = TRUE; break; }
    ReleaseSRWLockShared(&g_rules_lock);
    LONG was = InterlockedExchange(&dns_eligible_rules, eligible);
    // Rules arrive after Start in the GUI. Flush only on the first eligible rule,
    // after the workers/capture exist, so cached negative replies cannot bypass us.
    if (eligible && !was && dns_live && windivert_handle != INVALID_HANDLE_VALUE) flush_dns_resolver_cache();
}

BOOL dns_question(const UINT8 *data, int len, PB_DNS_QUESTION *out)
{
    if (!data || !out || len < 17 || dns_u16(data + 4) != 1 || (data[2] & 0x78)) return FALSE;
    int offset = 12;
    if (!dns_parse_name(data, len, &offset, out->name, sizeof(out->name)) || offset > len - 4) return FALSE;
    if (!out->name[0] || dns_u16(data + offset + 2) != 1) return FALSE;
    // Only printable DNS host/service names are used in rule matching/logs.
    for (char *p = out->name; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.')) return FALSE;
    out->type = dns_u16(data + offset); out->end = offset + 4;
    return TRUE;
}

BOOL dns_local_name(const char *name)
{
    static const char *suffixes[] = {".local", ".localhost", ".localdomain", ".lan", ".home", ".internal", ".corp", ".intranet", ".arpa", ".test", ".invalid", ".example"};
    if (!name || !strchr(name, '.') || !_stricmp(name, "localhost")) return TRUE;
    size_t n = strlen(name);
    for (int i = 0; i < (int)(sizeof(suffixes) / sizeof(suffixes[0])); i++) {
        size_t s = strlen(suffixes[i]);
        if (n >= s && !_stricmp(name + n - s, suffixes[i])) return TRUE;
    }
    return FALSE;
}

BOOL dns_response_valid(const UINT8 *query, int qlen, const UINT8 *answer, int alen)
{
    PB_DNS_QUESTION q, a;
    if (!dns_question(query, qlen, &q) || !dns_question(answer, alen, &a) ||
        !(answer[2] & 0x80) || query[0] != answer[0] || query[1] != answer[1] ||
        q.type != a.type || _stricmp(q.name, a.name)) return FALSE;
    // Check every section before accepting/snooping an answer. TC can contain a
    // partial record, but is retried over TCP rather than accepted as a result.
    int offset = a.end;
    UINT32 records = dns_u16(answer + 6) + dns_u16(answer + 8) + dns_u16(answer + 10);
    for (UINT32 i = 0; i < records; i++) {
        char ignored[256];
        if (!dns_parse_name(answer, alen, &offset, ignored, sizeof(ignored)) || offset > alen - 10) return FALSE;
        int bytes = dns_u16(answer + offset + 8); offset += 10;
        if (bytes > alen - offset) return FALSE;
        offset += bytes;
    }
    return offset == alen;
}

BOOL dns_response_retry(const UINT8 *answer, int len)
{
    if (!answer || len < 12) return TRUE;
    int rcode = answer[3] & 15;
    return (answer[2] & 2) || rcode == 2 || rcode == 5;
}

BOOL dns_proxy_policy(const char *process, BOOL system_dns, const char *domain, UINT32 *config_id)
{
    if (!g_proxy_enabled || (domain && dns_local_name(domain))) return FALSE;
    BOOL selected = FALSE;
    AcquireSRWLockShared(&g_rules_lock);
    for (PROCESS_RULE *rule = rules_list; rule; rule = rule->next) {
        if (!rule->enabled) continue;
        BOOL any = !strcmp(rule->process_name, "*") || !strcmp(rule->process_name, "ANY");
        if (!system_dns && !any && (!process || !match_process_list(rule->process_name, process))) continue;
        // A shared Dnscache flow has no trustworthy originating app identity.
        // App-specific DIRECT/BLOCK rules must not veto other apps' fallback.
        if (system_dns && !any && rule->action != RULE_ACTION_PROXY) continue;
        BOOL domain_filter = rule_has_domain_filter(rule);
        BOOL ip_filter = rule->target_hosts && rule->target_hosts[0] && strcmp(rule->target_hosts, "*");
        if (domain_filter) {
            if (domain ? !match_domain_list(rule->target_domains, domain) : rule->action != RULE_ACTION_PROXY) continue;
        } else if (ip_filter) continue; // unresolved names cannot safely match IP-only rules (e.g. Local DIRECT)
        if (rule->action != RULE_ACTION_PROXY) break;
        PROXY_CONFIG proxy;
        if (dns_config_copy(rule->proxy_config_id, &proxy)) {
            *config_id = proxy.config_id; selected = TRUE;
            ZeroMemory(&pb_log_context, sizeof(pb_log_context));
            pb_log_context.rule_id = rule->rule_id;
            strcpy_s(pb_log_context.rule_name, sizeof(pb_log_context.rule_name), rule->name);
            strcpy_s(pb_log_context.match, sizeof(pb_log_context.match), "DNS: local-first with proxy fallback");
            if (process) strncpy_s(pb_log_context.process, sizeof(pb_log_context.process), extract_filename(process), _TRUNCATE);
            g_tl_rule_id = rule->rule_id; g_tl_rule_localhost = FALSE;
        }
        break;
    }
    ReleaseSRWLockShared(&g_rules_lock);
    return selected;
}

static SOCKET dns_socket(int af, BOOL udp)
{
    if (dns_stopping) return INVALID_SOCKET;
    SOCKET s = socket(af, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return s;
    DWORD timeout = 500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    AcquireSRWLockExclusive(&dns_socket_lock);
    for (int i = 0; i < DNS_SOCKETS && !dns_stopping; i++) if (!dns_sockets[i].used) {
        dns_sockets[i].socket = s; dns_sockets[i].used = TRUE;
        ReleaseSRWLockExclusive(&dns_socket_lock);
        return s;
    }
    ReleaseSRWLockExclusive(&dns_socket_lock);
    closesocket(s); return INVALID_SOCKET;
}

static void dns_close(SOCKET s)
{
    if (s == INVALID_SOCKET) return;
    AcquireSRWLockExclusive(&dns_socket_lock);
    for (int i = 0; i < DNS_SOCKETS; i++) if (dns_sockets[i].used && dns_sockets[i].socket == s) {
        dns_sockets[i].used = FALSE; break;
    }
    closesocket(s); // serialized with stop: never shut down a recycled socket handle
    ReleaseSRWLockExclusive(&dns_socket_lock);
}

static BOOL dns_io(SOCKET s, UINT8 *data, int bytes, BOOL writing, ULONGLONG deadline)
{
    int offset = 0;
    while (offset < bytes && !dns_stopping && GetTickCount64() < deadline) {
        fd_set set; FD_ZERO(&set); FD_SET(s, &set);
        struct timeval tv = {0, 100000};
        int ready = select(0, writing ? NULL : &set, writing ? &set : NULL, NULL, &tv);
        if (ready == SOCKET_ERROR) return FALSE;
        if (!ready) continue;
        int n = writing ? send(s, (char*)data + offset, bytes - offset, 0) : recv(s, (char*)data + offset, bytes - offset, 0);
        if (n <= 0) return FALSE;
        offset += n;
    }
    return offset == bytes;
}

// DNS tunnels use their own bounded handshake so shutdown cancels slow/fragmented
// proxy replies too, without changing the general TCP relay's handshake behavior.
static BOOL dns_tunnel(SOCKET s, const PROXY_CONFIG *proxy, UINT32 target, ULONGLONG deadline)
{
    UINT8 b[2048];
    if (proxy->type == PROXY_TYPE_SOCKS5) {
        b[0] = 5; b[1] = proxy->username[0] ? 2 : 1; b[2] = 0; b[3] = 2;
        if (!dns_io(s, b, b[1] + 2, TRUE, deadline) || !dns_io(s, b, 2, FALSE, deadline) || b[0] != 5) return FALSE;
        if (b[1] == 2 && proxy->username[0]) {
            size_t u = strlen(proxy->username), p = strlen(proxy->password);
            b[0] = 1; b[1] = (UINT8)u; memcpy(b + 2, proxy->username, u);
            b[2 + u] = (UINT8)p; memcpy(b + 3 + u, proxy->password, p);
            if (!dns_io(s, b, (int)(3 + u + p), TRUE, deadline) || !dns_io(s, b, 2, FALSE, deadline) || b[0] != 1 || b[1]) return FALSE;
        } else if (b[1] != 0) return FALSE;
        b[0] = 5; b[1] = 1; b[2] = 0; b[3] = 1; memcpy(b + 4, &target, 4); b[8] = 0; b[9] = 53;
        if (!dns_io(s, b, 10, TRUE, deadline) || !dns_io(s, b, 4, FALSE, deadline) || b[0] != 5 || b[1] || b[2]) return FALSE;
        int n = b[3] == 1 ? 6 : b[3] == 4 ? 18 : 0;
        if (b[3] == 3) { if (!dns_io(s, b, 1, FALSE, deadline)) return FALSE; n = b[0] + 2; }
        return n && dns_io(s, b, n, FALSE, deadline);
    }
    char ip[32], auth[1100] = "", request[2048]; format_ip_address(target, ip, sizeof(ip));
    if (proxy->username[0]) {
        char pair[514], encoded[700];
        snprintf(pair, sizeof(pair), "%s:%s", proxy->username, proxy->password);
        base64_encode(pair, encoded, sizeof(encoded));
        snprintf(auth, sizeof(auth), "Proxy-Authorization: Basic %s\r\n", encoded);
    }
    int n = snprintf(request, sizeof(request), "CONNECT %s:53 HTTP/1.1\r\nHost: %s:53\r\n%s\r\n", ip, ip, auth);
    if (n < 0 || n >= (int)sizeof(request) || !dns_io(s, (UINT8*)request, n, TRUE, deadline)) return FALSE;
    // Read exactly the header: never eat the DNS stream following it.
    int used = 0;
    while (used < (int)sizeof(b) - 1) {
        if (!dns_io(s, b + used, 1, FALSE, deadline)) return FALSE;
        used++;
        if (used >= 4 && !memcmp(b + used - 4, "\r\n\r\n", 4)) break;
    }
    b[used] = 0;
    int code = 0;
    return used < (int)sizeof(b) - 1 && sscanf_s((char*)b, "HTTP/%*u.%*u %d", &code) == 1 && code == 200;
}

static int dns_tcp_query(const UINT8 *query, int qlen, UINT8 *answer, int cap,
                         const struct sockaddr *resolver, int resolver_len, const PROXY_CONFIG *proxy, UINT32 target, int timeout)
{
    SOCKET s = dns_socket(proxy ? AF_INET : resolver->sa_family, FALSE);
    if (s == INVALID_SOCKET) return 0;
    ULONGLONG deadline = GetTickCount64() + timeout;
    struct sockaddr_in endpoint = {0}; endpoint.sin_family = AF_INET;
    if (proxy) { endpoint.sin_addr.s_addr = proxy->resolved_ip; endpoint.sin_port = htons(proxy->port); }
    const struct sockaddr *dest = proxy ? (struct sockaddr*)&endpoint : resolver;
    int dest_len = proxy ? sizeof(endpoint) : resolver_len;
    int result = 0;
    if (!connect_with_timeout(s, dest, dest_len, timeout) && (!proxy || dns_tunnel(s, proxy, target, deadline))) {
        UINT8 prefix[2]; dns_put16(prefix, qlen);
        if (dns_io(s, prefix, 2, TRUE, deadline) && dns_io(s, (UINT8*)query, qlen, TRUE, deadline) && dns_io(s, prefix, 2, FALSE, deadline)) {
            int n = dns_u16(prefix);
            if (n >= 12 && n <= cap && dns_io(s, answer, n, FALSE, deadline) && dns_response_valid(query, qlen, answer, n)) result = n;
        }
    }
    dns_close(s); return result;
}

int dns_proxy_exchange(const UINT8 *query, int qlen, UINT8 *answer, int cap,
                       const struct sockaddr *resolver, int resolver_len, BOOL tcp, const PROXY_CONFIG *proxy)
{
    PB_DNS_QUESTION question;
    if (!dns_question(query, qlen, &question) || (query[2] & 0x80) || qlen > PB_DNS_MAX || cap < 12) return 0;
    int n = 0;
    if (tcp) n = dns_tcp_query(query, qlen, answer, cap, resolver, resolver_len, NULL, 0, DNS_LOCAL_MS);
    else {
        SOCKET s = dns_socket(resolver->sa_family, TRUE);
        if (s != INVALID_SOCKET) {
            if (!connect(s, resolver, resolver_len) && send(s, (const char*)query, qlen, 0) == qlen) {
                ULONGLONG until = GetTickCount64() + DNS_LOCAL_MS;
                while (!dns_stopping && GetTickCount64() < until) {
                    fd_set reads; FD_ZERO(&reads); FD_SET(s, &reads); struct timeval tv = {0, 50000};
                    int ready = select(0, &reads, NULL, NULL, &tv);
                    if (ready < 0) break;
                    if (!ready) continue;
                    int got = recv(s, (char*)answer, cap, 0);
                    if (got > 0 && dns_response_valid(query, qlen, answer, got)) { n = got; break; }
                }
            }
            dns_close(s);
        }
    }
    if (n && !dns_response_retry(answer, n)) { snoop_dns_response(answer, n); return n; }
    if (proxy && !dns_local_name(question.name)) {
        const char *upstreams[] = {"1.1.1.1", "9.9.9.9"};
        for (int i = 0; i < 2 && !dns_stopping; i++) {
            n = dns_tcp_query(query, qlen, answer, cap, resolver, resolver_len, proxy, parse_ipv4(upstreams[i]), DNS_REMOTE_MS);
            if (n && !dns_response_retry(answer, n)) {
                snoop_dns_response(answer, n);
                log_message("[DNS] %s type=%u: local DNS failed; resolved through %s proxy config=%u via %s:53",
                    question.name, question.type, proxy->type == PROXY_TYPE_HTTP ? "HTTP" : "SOCKS5", proxy->config_id, upstreams[i]);
                return n;
            }
        }
        if (!dns_stopping)
            log_message("[DNS] %s type=%u: original resolver and proxy config=%u DNS fallback failed; returning SERVFAIL",
                        question.name, question.type, proxy->config_id);
    }
    return 0;
}

static int dns_error(const UINT8 *query, int qlen, UINT8 *answer, int cap)
{
    PB_DNS_QUESTION q;
    if (!dns_question(query, qlen, &q) || q.end > cap) return 0;
    memcpy(answer, query, q.end); answer[2] = (UINT8)(0x80 | (query[2] & 1)); answer[3] = (UINT8)(0x80 | (query[3] & 0x10) | 2);
    memset(answer + 6, 0, 6); return q.end;
}

int dns_proxy_make_reply(const UINT8 *packet, UINT len, const UINT8 *answer, int alen, UINT8 *out, UINT cap, WINDIVERT_ADDRESS *addr)
{
    PWINDIVERT_IPHDR ip4 = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_UDPHDR udp = NULL;
    PVOID payload = NULL; UINT payload_len = 0;
    if (!packet || !answer || !out || !addr || alen < 12 || !WinDivertHelperParsePacket(packet, len, &ip4, &ip6, NULL, NULL, NULL, NULL, &udp, &payload, &payload_len, NULL, NULL) || !udp) return 0;
    if (ntohs(udp->Length) != payload_len + 8) return 0;
    UINT prefix = (UINT)((const UINT8*)payload - packet);
    if ((!ip4 && !ip6) || !dns_response_valid(payload, payload_len, answer, alen)) return 0;
    // Cap UDP DNS payload to avoid IP fragmentation on either family. A large
    // answer gets TC and the original question, so the app retries via TCP.
    PB_DNS_QUESTION q;
    BOOL truncated = alen > 512;
    if (truncated) { if (!dns_question(payload, payload_len, &q)) return 0; alen = q.end; }
    if (prefix + alen > cap || prefix + alen > 65535) return 0;
    memcpy(out, packet, prefix);
    memcpy(out + prefix, truncated ? payload : answer, alen);
    if (truncated) {
        out[prefix + 2] = answer[2] | 2; out[prefix + 3] = answer[3];
        memset(out + prefix + 6, 0, 6);
    }
    PWINDIVERT_UDPHDR reply_udp = (PWINDIVERT_UDPHDR)(out + ((const UINT8*)udp - packet));
    UINT16 port = reply_udp->SrcPort; reply_udp->SrcPort = reply_udp->DstPort; reply_udp->DstPort = port;
    reply_udp->Length = htons((UINT16)(8 + alen));
    if (ip4) {
        PWINDIVERT_IPHDR reply = (PWINDIVERT_IPHDR)out;
        UINT32 temp = reply->SrcAddr; reply->SrcAddr = reply->DstAddr; reply->DstAddr = temp;
        reply->Length = htons((UINT16)(prefix + alen)); reply->TTL = 64;
        if ((reply->DstAddr & 255) != 127) addr->Outbound = FALSE;
    } else {
        PWINDIVERT_IPV6HDR reply = (PWINDIVERT_IPV6HDR)out; UINT32 temp[4];
        memcpy(temp, reply->SrcAddr, 16); memcpy(reply->SrcAddr, reply->DstAddr, 16); memcpy(reply->DstAddr, temp, 16);
        reply->Length = htons((UINT16)(prefix + alen - 40)); reply->HopLimit = 64;
        static const UINT8 loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(reply->DstAddr, loopback, 16)) addr->Outbound = FALSE;
    }
    WinDivertHelperCalcChecksums(out, prefix + alen, addr, 0);
    return (int)(prefix + alen);
}

static BOOL dns_owner(BOOL v6, const void *src, UINT16 port, BOOL tcp, char *process, DWORD *pid)
{
    *pid = v6 ? (tcp ? get_process_id_from_connection_v6(src, port) : get_process_id_from_udp_connection_v6(src, port)) :
        (tcp ? get_process_id_from_connection(*(const UINT32*)src, port) : get_process_id_from_udp_connection(*(const UINT32*)src, port));
    return *pid && *pid != g_current_process_id && get_process_name_from_pid(*pid, process, MAX_PROCESS_NAME);
}

static DWORD WINAPI dns_worker(LPVOID unused)
{
    (void)unused;
    UINT8 answer[PB_DNS_MAX], reply[MAXBUF];
    while (!dns_stopping) {
        WaitForSingleObject(dns_ready, INFINITE);
        AcquireSRWLockExclusive(&dns_job_lock);
        DNS_JOB *job = dns_head;
        if (job) { dns_head = job->next; dns_queued--; if (!dns_head) dns_tail = NULL; }
        ReleaseSRWLockExclusive(&dns_job_lock);
        if (!job) continue;
        PWINDIVERT_IPHDR ip4 = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_UDPHDR udp = NULL; PVOID query; UINT qlen;
        WinDivertHelperParsePacket(job->packet, job->len, &ip4, &ip6, NULL, NULL, NULL, NULL, &udp, &query, &qlen, NULL, NULL);
        struct sockaddr_storage resolver = {0}; int resolver_len;
        if (ip4) { struct sockaddr_in *r = (struct sockaddr_in*)&resolver; r->sin_family = AF_INET; r->sin_addr.s_addr = ip4->DstAddr; r->sin_port = udp->DstPort; resolver_len = sizeof(*r); }
        else {
            struct sockaddr_in6 *r = (struct sockaddr_in6*)&resolver;
            r->sin6_family = AF_INET6; memcpy(&r->sin6_addr, ip6->DstAddr, 16); r->sin6_port = udp->DstPort;
            if (IN6_IS_ADDR_LINKLOCAL(&r->sin6_addr)) r->sin6_scope_id = job->addr.Network.IfIdx;
            resolver_len = sizeof(*r);
        }
        int n = dns_proxy_exchange(query, qlen, answer, PB_DNS_MAX, (struct sockaddr*)&resolver, resolver_len, FALSE, &job->proxy);
        if (!n) n = dns_error(query, qlen, answer, PB_DNS_MAX);
        if (n && !dns_stopping) {
            int bytes = dns_proxy_make_reply(job->packet, job->len, answer, n, reply, MAXBUF, &job->addr);
            if (bytes && !WinDivertSend(windivert_handle, reply, bytes, NULL, &job->addr) && !dns_stopping)
                log_message("[DNS] Could not return DNS response (%lu)", GetLastError());
        }
        free(job);
    }
    return 0;
}

BOOL dns_proxy_start(void)
{
    if (dns_live) return TRUE;
    dns_service_pid = 0;
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceW(scm, L"Dnscache", SERVICE_QUERY_STATUS);
        SERVICE_STATUS_PROCESS status; DWORD needed;
        if (svc) { if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &needed)) dns_service_pid = status.dwProcessId; CloseServiceHandle(svc); }
        CloseServiceHandle(scm);
    }
    dns_ready = CreateSemaphoreW(NULL, 0, DNS_QUEUE + DNS_WORKERS, NULL);
    if (!dns_ready) return FALSE;
    InterlockedExchange(&dns_stopping, 0);
    for (int i = 0; i < DNS_WORKERS; i++) {
        dns_workers[i] = CreateThread(NULL, 0, dns_worker, NULL, 0, NULL);
        if (!dns_workers[i]) { dns_proxy_stop(); return FALSE; }
    }
    InterlockedExchange(&dns_live, 1);
    dns_proxy_rules_changed();
    if (dns_eligible_rules && windivert_handle != INVALID_HANDLE_VALUE) flush_dns_resolver_cache();
    log_message("[DNS] Local-first UDP/TCP DNS fallback enabled (SOCKS5/HTTP TCP, no system DNS changes)");
    return TRUE;
}

void dns_proxy_stop(void)
{
    InterlockedExchange(&dns_live, 0); InterlockedExchange(&dns_stopping, 1);
    AcquireSRWLockExclusive(&dns_socket_lock);
    for (int i = 0; i < DNS_SOCKETS; i++) if (dns_sockets[i].used) shutdown(dns_sockets[i].socket, SD_BOTH);
    ReleaseSRWLockExclusive(&dns_socket_lock);
    if (dns_ready) ReleaseSemaphore(dns_ready, DNS_WORKERS, NULL);
    for (int i = 0; i < DNS_WORKERS; i++) if (dns_workers[i]) { WaitForSingleObject(dns_workers[i], INFINITE); CloseHandle(dns_workers[i]); dns_workers[i] = NULL; }
    if (dns_ready) { CloseHandle(dns_ready); dns_ready = NULL; }
    AcquireSRWLockExclusive(&dns_job_lock);
    while (dns_head) { DNS_JOB *job = dns_head; dns_head = job->next; free(job); }
    dns_tail = NULL; dns_queued = 0;
    ReleaseSRWLockExclusive(&dns_job_lock);
}

BOOL dns_proxy_intercept(const UINT8 *packet, UINT len, const WINDIVERT_ADDRESS *addr)
{
    if (!dns_live || !dns_eligible_rules || !g_proxy_enabled || !addr->Outbound) return FALSE;
    PWINDIVERT_IPHDR ip4 = NULL; PWINDIVERT_IPV6HDR ip6 = NULL; PWINDIVERT_UDPHDR udp = NULL; PVOID payload; UINT qlen;
    if (!WinDivertHelperParsePacket(packet, len, &ip4, &ip6, NULL, NULL, NULL, NULL, &udp, &payload, &qlen, NULL, NULL) || !udp || udp->DstPort != htons(53) || (!ip4 && !ip6) || qlen > 4096) return FALSE;
    if (ntohs(udp->Length) != qlen + 8 ||
        (ip4 && (WINDIVERT_IPHDR_GET_MF(ip4) || WINDIVERT_IPHDR_GET_FRAGOFF(ip4))) ||
        (ip6 && ip6->NextHdr != IPPROTO_UDP)) return FALSE; // leave fragmented/extension-header DNS to the original path
    PB_DNS_QUESTION q;
    if (!dns_question(payload, qlen, &q) || (((UINT8*)payload)[2] & 0x80) || dns_local_name(q.name)) return FALSE;
    char process[MAX_PROCESS_NAME]; DWORD pid; UINT32 proxy_id;
    if (!dns_owner(ip6 != NULL, ip4 ? (const void*)&ip4->SrcAddr : (const void*)ip6->SrcAddr, ntohs(udp->SrcPort), FALSE, process, &pid) ||
        !dns_proxy_policy(process, pid == dns_service_pid, q.name, &proxy_id)) return FALSE;
    DNS_JOB *job = (DNS_JOB*)malloc(sizeof(*job) + len);
    if (!job) return FALSE;
    if (!dns_config_copy(proxy_id, &job->proxy)) { free(job); return FALSE; }
    job->next = NULL; job->addr = *addr; job->len = len; memcpy(job->packet, packet, len);
    AcquireSRWLockExclusive(&dns_job_lock);
    if (dns_queued >= DNS_QUEUE || !dns_live) { ReleaseSRWLockExclusive(&dns_job_lock); free(job); return FALSE; }
    if (dns_tail) dns_tail->next = job; else dns_head = job;
    dns_tail = job; dns_queued++; ReleaseSemaphore(dns_ready, 1, NULL);
    ReleaseSRWLockExclusive(&dns_job_lock);
    return TRUE;
}

BOOL dns_proxy_tcp_candidate(BOOL v6, const void *src, UINT16 port, UINT32 *config_id, DWORD *pid)
{
    if (!dns_live || !dns_eligible_rules) return FALSE;
    char process[MAX_PROCESS_NAME];
    BOOL eligible = dns_owner(v6, src, port, TRUE, process, pid) && dns_proxy_policy(process, *pid == dns_service_pid, NULL, config_id);
    if (eligible) pb_log_context.pid = *pid;
    return eligible;
}

void dns_proxy_mark_tcp(UINT16 port, BOOL v6)
{
    AcquireSRWLockExclusive(&lock);
    for (CONNECTION_INFO *c = connection_hash_table[port % CONNECTION_HASH_SIZE]; c; c = c->next)
        if (c->src_port == port && !c->is_udp && c->is_ipv6 == v6) { c->dns_proxy = TRUE; break; }
    ReleaseSRWLockExclusive(&lock);
}

BOOL dns_proxy_is_tcp(UINT16 port, BOOL v6)
{
    BOOL result = FALSE;
    AcquireSRWLockShared(&lock);
    for (CONNECTION_INFO *c = connection_hash_table[port % CONNECTION_HASH_SIZE]; c; c = c->next)
        if (c->src_port == port && !c->is_udp && c->is_ipv6 == v6) { result = c->dns_proxy; break; }
    ReleaseSRWLockShared(&lock);
    return result;
}

void dns_proxy_tcp_client(const CONNECTION_CONFIG *config)
{
    SOCKET client = config->client_socket;
    if (InterlockedIncrement(&dns_tcp_clients) > 32) { InterlockedDecrement(&dns_tcp_clients); closesocket(client); return; }
    DWORD timeout = 500;
    setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));
    UINT8 *query = (UINT8*)malloc(PB_DNS_MAX), *answer = (UINT8*)malloc(PB_DNS_MAX);
    char process[MAX_PROCESS_NAME] = ""; get_process_name_from_pid(config->pid, process, sizeof(process));
    struct sockaddr_storage resolver = {0}; int resolver_len;
    if (config->is_ipv6) {
        struct sockaddr_in6 *r = (struct sockaddr_in6*)&resolver;
        r->sin6_family = AF_INET6; memcpy(&r->sin6_addr, config->orig_dest_ip6, 16); r->sin6_port = htons(config->orig_dest_port);
        if (IN6_IS_ADDR_LINKLOCAL(&r->sin6_addr)) {
            struct sockaddr_in6 local = {0}; int local_len = sizeof(local);
            if (!getsockname(client, (struct sockaddr*)&local, &local_len)) r->sin6_scope_id = local.sin6_scope_id;
        }
        resolver_len = sizeof(*r);
    }
    else { struct sockaddr_in *r = (struct sockaddr_in*)&resolver; r->sin_family = AF_INET; r->sin_addr.s_addr = config->orig_dest_ip; r->sin_port = htons(config->orig_dest_port); resolver_len = sizeof(*r); }
    while (query && answer && !dns_stopping) {
        UINT8 prefix[2];
        if (!dns_io(client, prefix, 2, FALSE, GetTickCount64() + 30000)) break;
        int len = dns_u16(prefix);
        if (len < 17 || len > PB_DNS_MAX || !dns_io(client, query, len, FALSE, GetTickCount64() + 3000)) break;
        PB_DNS_QUESTION q; if (!dns_question(query, len, &q)) break;
        UINT32 id; PROXY_CONFIG snapshot, *proxy = NULL;
        if (dns_proxy_policy(process, config->pid == dns_service_pid, q.name, &id)) {
            if (dns_config_copy(id, &snapshot)) proxy = &snapshot;
        }
        int n = dns_proxy_exchange(query, len, answer, PB_DNS_MAX, (struct sockaddr*)&resolver, resolver_len, TRUE, proxy);
        if (!n) n = dns_error(query, len, answer, PB_DNS_MAX);
        dns_put16(prefix, n);
        if (!n || !dns_io(client, prefix, 2, TRUE, GetTickCount64() + 1000) || !dns_io(client, answer, n, TRUE, GetTickCount64() + 1000)) break;
    }
    free(query); free(answer); closesocket(client); InterlockedDecrement(&dns_tcp_clients);
}
