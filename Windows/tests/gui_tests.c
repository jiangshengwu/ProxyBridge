// Include the actual filtering implementation without starting the application or driver.
#include "../gui/main.c"
#include <assert.h>

static COLORREF text_colour(HWND edit, const wchar_t *text)
{
    FINDTEXTEXW find = {{0,-1}, text, {0,0}};
    assert(SendMessageW(edit, EM_FINDTEXTEXW, FR_DOWN, (LPARAM)&find) >= 0);
    SendMessageW(edit, EM_EXSETSEL, 0, (LPARAM)&find.chrgText);
    CHARFORMAT2W format = {0}; format.cbSize = sizeof(format);
    SendMessageW(edit, EM_GETCHARFORMAT, SCF_SELECTION, (LPARAM)&format);
    assert(format.dwMask & CFM_COLOR);
    return format.crTextColor;
}

static void test_rich_logs(void)
{
    assert(LoadLibraryExW(L"Msftedit.dll",NULL,LOAD_LIBRARY_SEARCH_SYSTEM32));
    HWND parent = CreateWindowExW(0,L"STATIC",L"Log rendering test",WS_OVERLAPPED,0,0,900,200,NULL,NULL,GetModuleHandleW(NULL),NULL);
    HWND edit = CreateWindowExW(0,MSFTEDIT_CLASS,L"",WS_CHILD | ES_MULTILINE | ES_READONLY,0,0,900,200,parent,NULL,GetModuleHandleW(NULL),NULL);
    assert(parent && edit);
    SendMessageW(edit,EM_EXLIMITTEXT,0,MAX_LOG_CHARS*2);
    const wchar_t *sample = L"[2026-09-06 12:34:56] 应用.exe (PID:42) -> 2001:db8::1:443  via Proxy SOCKS5 (TCP) | status=CONNECTED | rule=R2 测试{代理}\\路径 | match=APP:C:\\Apps\\* | Ready\r\n";
    AppendToEdit(edit,sample);
    assert(!(GetWindowLongPtrW(edit,GWL_STYLE) & WS_VISIBLE));
    wchar_t plain[1024]; GETTEXTEX get = {sizeof(plain),GT_USECRLF,1200,NULL,NULL};
    SendMessageW(edit,EM_GETTEXTEX,(WPARAM)&get,(LPARAM)plain);
    assert(!wcscmp(plain,sample)); // RTF escaping must round-trip Unicode, braces and backslashes
    assert(text_colour(edit,L"应用.exe") == g_logColors[LC_GREEN]);
    assert(text_colour(edit,L"2001:db8::1:443") == g_logColors[LC_ORANGE]);
    assert(text_colour(edit,L"SOCKS5") == g_logColors[LC_PURPLE]);
    assert(text_colour(edit,L"(TCP)") == g_logColors[LC_BLUE]);
    assert(text_colour(edit,L"CONNECTED") == g_logColors[LC_GREEN]);
    assert(text_colour(edit,L"测试{代理}") == g_logColors[LC_TEAL]);
    AppendToEdit(edit,L"[2026-09-06 12:34:57] app.exe (PID:43) -> 1.2.3.4:443  via Proxy | status=AUTH_FAILED | rule=R2 Test\r\n");
    assert(text_colour(edit,L"AUTH_FAILED") == g_logColors[LC_RED]);
    AppendToEdit(edit,L"[2026-09-06 12:34:58] [CORE] WARN: timeout\r\n");
    assert(text_colour(edit,L"[CORE]") == g_logColors[LC_PURPLE]);
    assert(text_colour(edit,L"WARN: timeout") == g_logColors[LC_AMBER]);
    g_connStore.edit=edit; g_connStore.count=1; g_connStore.lines[0]=(wchar_t*)sample;
    LogStoreRebuild(&g_connStore);
    assert(text_colour(edit,L"CONNECTED") == g_logColors[LC_GREEN]);
    g_connStore.count=0; g_connStore.edit=NULL;
    DestroyWindow(edit); DestroyWindow(parent);
}

static void queue_test_lines(LogStore *store, int count)
{
    for (int i=0; i<count; i++) {
        wchar_t line[80]; _snwprintf_s(line,80,_TRUNCATE,L"Event %d: scroll regression test\r\n",i);
        LogStoreQueue(store,_wcsdup(line));
    }
    assert(LogStoreFlush(store)==count);
}

static void test_follow_bottom(void)
{
    HWND parent=CreateWindowExW(0,L"STATIC",L"Scroll test",WS_OVERLAPPED,0,0,600,160,NULL,NULL,GetModuleHandleW(NULL),NULL);
    HWND edits[2]; LogStore *stores=(LogStore*)calloc(2,sizeof(LogStore)); assert(stores);
    for (int i=0; i<2; i++) {
        edits[i]=CreateWindowExW(0,MSFTEDIT_CLASS,L"",WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            0,0,600,160,parent,NULL,GetModuleHandleW(NULL),NULL);
        assert(edits[i]); SendMessageW(edits[i],EM_EXLIMITTEXT,0,MAX_LOG_CHARS*2);
        LogStoreInit(&stores[i],edits[i]);
    }
    BOOL autoClear=g_autoClear; g_autoClear=FALSE;
    queue_test_lines(&stores[0],120); queue_test_lines(&stores[1],120);
    assert(LogIsAtBottom(edits[0]) && LogIsAtBottom(edits[1])); // initial follow
    CHARRANGE selection={10,20}; SendMessageW(edits[0],EM_EXSETSEL,0,(LPARAM)&selection);
    SendMessageW(edits[0],WM_VSCROLL,SB_BOTTOM,0);
    SendMessageW(edits[0],WM_VSCROLL,SB_PAGEUP,0);
    assert(!LogIsAtBottom(edits[0]));
    POINT before, after; SendMessageW(edits[0],EM_GETSCROLLPOS,0,(LPARAM)&before);
    int displayed=GetWindowTextLengthW(edits[0]);
    g_autoClear=TRUE;
    queue_test_lines(&stores[0],550); // auto-clear and incoming bursts must not disturb reading
    assert(stores[0].viewDirty && stores[0].count==670);
    assert(GetWindowTextLengthW(edits[0])==displayed);
    SendMessageW(edits[0],EM_GETSCROLLPOS,0,(LPARAM)&after);
    assert(before.x==after.x && before.y==after.y);
    CHARRANGE retained; SendMessageW(edits[0],EM_EXGETSEL,0,(LPARAM)&retained);
    assert(retained.cpMin==selection.cpMin && retained.cpMax==selection.cpMax);
    queue_test_lines(&stores[1],5); // other tab still follows independently
    assert(LogIsAtBottom(edits[1]) && !stores[1].viewDirty);
    g_autoClear=FALSE;
    SendMessageW(edits[0],WM_VSCROLL,SB_BOTTOM,0);
    assert(!stores[0].viewDirty && LogIsAtBottom(edits[0])); // catch up without another incoming event
    assert(GetWindowTextLengthW(edits[0])>displayed);
    queue_test_lines(&stores[0],3);
    assert(LogIsAtBottom(edits[0])); // follow resumed
    SendMessageW(edits[0],WM_VSCROLL,SB_LINEUP,0);
    assert(!LogIsAtBottom(edits[0]));
    queue_test_lines(&stores[0],1); assert(stores[0].viewDirty);
    LogStoreClear(&stores[0]);
    queue_test_lines(&stores[0],2);
    assert(!stores[0].viewDirty && LogIsAtBottom(edits[0]));
    for (int i=0; i<2; i++) { LogStoreFree(&stores[i]); DestroyWindow(edits[i]); }
    DestroyWindow(parent); free(stores); g_autoClear=autoClear;
}

int main(void)
{
    const wchar_t *tcp = L"[2026-09-06 12:34:56] chrome.exe (PID:42) -> 2001:db8::1:443  via Proxy SOCKS5://127.0.0.1:1080 (TCP) | status=CONNECTED | rule=R2 Browser\r\n";
    const wchar_t *udp = L"[2026-09-06 12:34:56] game.exe (PID:43) -> 1.2.3.4:53  via Direct (UDP) | status=DIRECT\r\n";
    wchar_t proc[260], ip[128], port[16]; const wchar_t *proto, *action;
    assert(ConnectionFields(tcp, proc, ip, port, &proto, &action));
    assert(!wcscmp(proc,L"chrome.exe") && !wcscmp(ip,L"2001:db8::1") && !wcscmp(port,L"443"));
    assert(!wcscmp(proto,L"TCP") && !wcscmp(action,L"Proxy"));
    assert(LogLineMatches(&g_connStore,tcp));
    g_connStore.routeFilter = 2;
    assert(!LogLineMatches(&g_connStore,tcp) && LogLineMatches(&g_connStore,udp));
    g_connStore.protoFilter = 1;
    assert(!LogLineMatches(&g_connStore,udp));
    g_connStore.routeFilter = g_connStore.protoFilter = 0;
    wcscpy_s(g_connStore.filter,128,L"Browser");
    assert(LogLineMatches(&g_connStore,tcp) && !LogLineMatches(&g_connStore,udp));
    g_connStore.filter[0] = 0;
    const wchar_t *rejected = L"[2026-09-06 12:34:56] app.exe (PID:42) -> 1.2.3.4:443  via Proxy (TCP) | status=REJECTED | rule=R2 Test";
    g_connStore.routeFilter = 3;
    assert(LogLineMatches(&g_connStore,rejected) && !LogLineMatches(&g_connStore,tcp));
    g_connStore.routeFilter = 0;
    g_fltCount = 1;
    wcscpy_s(g_flt[0].mode,16,L"Exclude"); wcscpy_s(g_flt[0].proc,256,L"chrome.exe");
    assert(!LogLineMatches(&g_connStore,tcp) && LogLineMatches(&g_connStore,udp));
    g_fltCount = 0;
    assert(LogLineMatches(&g_connStore,tcp)); // changing filter restores retained entries
    g_actStore.sourceFilter = 1;
    assert(LogLineMatches(&g_actStore,L"[2026-09-06 12:34:56] [GUI] Started"));
    assert(!LogLineMatches(&g_actStore,L"[2026-09-06 12:34:56] [CORE] Started"));
    wchar_t timestamp[32]; GetTimePrefix(timestamp,32);
    assert(wcslen(timestamp)==22 && timestamp[5]==L'-' && timestamp[8]==L'-');
    PBLogCb("Late callback after shutdown");
    PBConnCb("app.exe",1,"1.2.3.4",443,"Proxy"); // disabled gate avoids touching freed/uninitialized stores
    test_rich_logs();
    test_follow_bottom();
    puts("PASS: log filters, RichEdit colours/Unicode, initial follow, pause/selection, resume, independent tabs, clear");
    return 0;
}
