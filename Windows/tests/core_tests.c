#include "../src/pb_internal.h"
#include <assert.h>

static int events;
static char last_event[2048];
static void capture(const char *process, DWORD pid, const char *ip, UINT16 port, const char *info)
{
    (void)process; (void)pid; (void)ip; (void)port;
    events++;
    strcpy_s(last_event, sizeof(last_event), info);
}

static void socket_pair(SOCKET *client, SOCKET *peer)
{
    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener != INVALID_SOCKET);
    struct sockaddr_in addr = {0}; addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    int len = sizeof(addr);
    assert(getsockname(listener, (struct sockaddr*)&addr, &len) == 0);
    assert(listen(listener, 1) == 0);
    *client = socket(AF_INET, SOCK_STREAM, 0);
    assert(connect_with_timeout(*client, (struct sockaddr*)&addr, len, 2000) == 0);
    *peer = accept(listener, NULL, NULL);
    assert(*peer != INVALID_SOCKET);
    configure_tcp_socket(*client, 4096, 1000);
    closesocket(listener);
}

static void test_rules(void)
{
    UINT32 ip = inet_addr("1.2.3.4"), cfg = 0;
    UINT8 ip6[16]; assert(inet_pton(AF_INET6, "2001:db8::1", ip6) == 1);
    UINT32 all = ProxyBridge_AddRule("*", "*", "*", "", RULE_PROTOCOL_BOTH, RULE_ACTION_BLOCK, 0, FALSE);
    UINT32 app = ProxyBridge_AddRule("chrome.exe", "*", "443", "", RULE_PROTOCOL_BOTH, RULE_ACTION_PROXY, 7, FALSE);
    assert(all && app);
    assert(match_rule("C:\\Apps\\chrome.exe", ip, 443, FALSE, &cfg) == RULE_ACTION_BLOCK);
    assert(match_rule_v6("chrome.exe", ip6, 443, FALSE, &cfg) == RULE_ACTION_BLOCK);
    assert(ProxyBridge_MoveRuleToPosition(app, 1));
    assert(ProxyBridge_SetRuleName(app, "Browser"));
    assert(match_rule("chrome.exe", ip, 443, FALSE, &cfg) == RULE_ACTION_PROXY && cfg == 7);
    assert(pb_log_context.rule_id == app && !strcmp(pb_log_context.rule_name, "Browser"));
    assert(g_tl_rule_id == app && !g_tl_rule_localhost);
    ProxyBridge_SetEnabled(FALSE);
    assert(match_rule("chrome.exe", ip, 443, FALSE, &cfg) == RULE_ACTION_DIRECT && pb_log_context.rule_id == 0);
    ProxyBridge_SetEnabled(TRUE);
    assert(match_rule_v6("chrome.exe", ip6, 443, TRUE, &cfg) == RULE_ACTION_PROXY);
    PB_LOG_CONTEXT snapshot = pb_log_context;
    add_connection(50001, TRUE, 0, ip, 443, 7, 42, snapshot.rule_id);
    assert(ProxyBridge_SetRuleName(app, "Renamed"));
    assert(ProxyBridge_DeleteRule(app));
    PB_LOG_CONTEXT saved;
    assert(get_log_context(50001, TRUE, FALSE, &saved));
    assert(saved.rule_id == snapshot.rule_id && !strcmp(saved.rule_name, "Browser"));
    udp_log_status(50001, FALSE, 1, "Sent");
    int before = events;
    udp_log_status(50001, FALSE, 1, "Sent again");
    assert(events == before); // one event per transition, not per datagram
    udp_log_status(50001, FALSE, 2, "Failed");
    assert(events == before + 1 && strstr(last_event, "status=FAILED"));
    remove_connection(50001, TRUE, FALSE);
    assert(ProxyBridge_DisableRule(all));
    assert(match_rule("chrome.exe", ip, 443, FALSE, &cfg) == RULE_ACTION_DIRECT);
    assert(pb_log_context.rule_id == 0);
    assert(ProxyBridge_DeleteRule(all));

    UINT32 limited = ProxyBridge_AddRule("*", "1.2.3.4", "443", "", RULE_PROTOCOL_TCP, RULE_ACTION_BLOCK, 0, FALSE);
    assert(match_rule("app.exe", ip, 443, FALSE, &cfg) == RULE_ACTION_BLOCK);
    assert(match_rule("app.exe", ip, 80, FALSE, &cfg) == RULE_ACTION_DIRECT);
    assert(match_rule("app.exe", ip, 443, TRUE, &cfg) == RULE_ACTION_DIRECT);
    assert(ProxyBridge_DeleteRule(limited));
    assert(match_process_pattern("C:\\Apps\\Browser\\*", "C:\\Apps\\Browser\\Helpers\\worker.exe"));
    assert(match_process_pattern("C:/Apps/Browser/*", "c:\\apps\\browser\\worker.exe"));
    assert(!match_process_pattern("C:\\Apps\\Browser\\*", "C:\\Apps\\BrowserOther\\worker.exe"));
    assert(!ProxyBridge_IsHealthy()); // inspecting health does not start interception
}

static void test_proxy_replies(void)
{
    const int errors[] = {0, 0, PB_ERROR_REJECTED, WSAENETUNREACH, WSAEHOSTUNREACH, WSAECONNREFUSED, WSAETIMEDOUT};
    for (int code = 2; code <= 6; code++) {
        SOCKET c, p; socket_pair(&c, &p);
        unsigned char reply[] = {5, (unsigned char)code, 0, 1};
        assert(send(p, (char*)reply, sizeof(reply), 0) == sizeof(reply));
        int received;
        assert(socks5_read_connect_reply(c, &received) == -1);
        assert(received == code && WSAGetLastError() == errors[code]);
        closesocket(c); closesocket(p);
    }
    SOCKET c, p; socket_pair(&c, &p);
    unsigned char auth[] = {5, 2, 1, 1}; // username/password selected, then rejected
    assert(send(p, (char*)auth, sizeof(auth), 0) == sizeof(auth));
    PROXY_CONFIG proxy = {0}; strcpy_s(proxy.username, sizeof(proxy.username), "user");
    strcpy_s(proxy.password, sizeof(proxy.password), "pass");
    assert(socks5_connect(c, inet_addr("1.2.3.4"), 443, &proxy) == -1);
    assert(WSAGetLastError() == WSAEACCES);
    closesocket(c); closesocket(p);
    socket_pair(&c, &p);
    const char *http = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
    assert(send(p, http, (int)strlen(http), 0) > 0);
    assert(http_connect(c, inet_addr("1.2.3.4"), 443, &proxy) == -1);
    assert(WSAGetLastError() == WSAEACCES);
    closesocket(c); closesocket(p);
    assert(!strcmp(connection_error_status(WSAETIMEDOUT), "TIMEOUT"));
    assert(!strcmp(connection_error_status(PB_ERROR_REJECTED), "REJECTED"));
}

static void test_relay_close(void)
{
    SOCKET app, relay_app, relay_proxy, proxy;
    socket_pair(&app, &relay_app);
    socket_pair(&relay_proxy, &proxy);
    TRANSFER_CONFIG *config = malloc(sizeof(*config)); assert(config);
    config->from_socket = relay_app; config->to_socket = relay_proxy;
    HANDLE thread = CreateThread(NULL, 0, transfer_handler, config, 0, NULL); assert(thread);
    assert(WaitForSingleObject(thread,1500)==WAIT_TIMEOUT); // receive polling must not expire idle sessions
    char buf[4];
    assert(send(app,"ping",4,0)==4 && recv_n(proxy,buf,4)==4 && !memcmp(buf,"ping",4));
    assert(send(proxy,"pong",4,0)==4 && recv_n(app,buf,4)==4 && !memcmp(buf,"pong",4));
    shutdown(proxy, SD_SEND);
    assert(WaitForSingleObject(thread,3000)==WAIT_OBJECT_0);
    DWORD result; assert(GetExitCodeThread(thread,&result) && result==0);
    CloseHandle(thread); closesocket(app); closesocket(proxy);
}

int main(void)
{
    WSADATA wsa; assert(WSAStartup(MAKEWORD(2,2), &wsa) == 0);
    ProxyBridge_SetConnectionCallback(capture);
    test_rules(); test_proxy_replies(); test_relay_close();
    WSACleanup();
    puts("PASS: rule order, IPv4/IPv6, rule snapshots, UDP transitions, folder scope, proxy errors, bidirectional relay/close");
    return 0;
}
