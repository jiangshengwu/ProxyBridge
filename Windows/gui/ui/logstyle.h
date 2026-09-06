// Build a single RTF batch so logs retain selectable text and per-field colours.
#ifndef PB_UI_LOGSTYLE_H
#define PB_UI_LOGSTYLE_H

enum { LC_TEXT, LC_DIM, LC_BLUE, LC_GREEN, LC_ORANGE, LC_PURPLE, LC_RED, LC_AMBER, LC_TEAL };
static const COLORREF g_logColors[] = {
    C_TEXT, C_DIM, RGB(0,122,255), RGB(40,167,69), RGB(245,124,0),
    RGB(175,52,222), RGB(255,59,48), RGB(214,155,0), RGB(0,158,181)
};
typedef struct { char *data; size_t length, capacity, offset; BOOL failed; } LogRtf;

static void RtfAdd(LogRtf *rtf, const char *text)
{
    if (rtf->failed) return;
    size_t n = strlen(text), required = rtf->length + n + 1;
    if (required > rtf->capacity) {
        size_t capacity = required > rtf->capacity * 2 ? required : rtf->capacity * 2;
        if (capacity < 4096) capacity = 4096;
        char *data = (char*)realloc(rtf->data, capacity);
        if (!data) { rtf->failed = TRUE; return; }
        rtf->data = data; rtf->capacity = capacity;
    }
    memcpy(rtf->data + rtf->length, text, n + 1); rtf->length += n;
}

static void RtfSpan(LogRtf *rtf, const wchar_t *start, const wchar_t *end, int colour)
{
    char token[32]; snprintf(token, sizeof(token), "\\cf%d ", colour + 1); RtfAdd(rtf, token);
    for (const wchar_t *p = start; p < end; p++) {
        if (*p == L'\\' || *p == L'{' || *p == L'}') {
            token[0] = '\\'; token[1] = (char)*p; token[2] = 0;
        } else if (*p == L'\t') strcpy_s(token, sizeof(token), "\\tab ");
        else if (*p < 32) continue;
        else if (*p < 127) { token[0] = (char)*p; token[1] = 0; }
        else snprintf(token, sizeof(token), "\\u%d?", (int)(short)*p);
        RtfAdd(rtf, token);
    }
}

static int LogStatusColour(const wchar_t *status)
{
    if (!wcsncmp(status,L"CONNECTED",9) || !wcsncmp(status,L"SUCCESS",7) || !wcsncmp(status,L"RELAYING",8)) return LC_GREEN;
    if (!wcsncmp(status,L"CONNECTING",10) || !wcsncmp(status,L"TIMEOUT",7) ||
        !wcsncmp(status,L"UNREACHABLE",11) || !wcsncmp(status,L"RESET",5)) return LC_AMBER;
    if (!wcsncmp(status,L"FAILED",6) || !wcsncmp(status,L"ERROR",5) || !wcsncmp(status,L"REJECTED",8) ||
        !wcsncmp(status,L"AUTH_FAILED",11) || !wcsncmp(status,L"REFUSED",7) || !wcsncmp(status,L"BLOCKED",7)) return LC_RED;
    return LC_DIM;
}

// All searches are confined to one NUL-terminated line, including unstructured core messages.
static void RtfLogLine(LogRtf *rtf, const wchar_t *line)
{
    const wchar_t *end = line + wcslen(line), *p = line;
    const wchar_t *stamp = wcsstr(p, L"] ");
    if (*p == L'[' && stamp) { RtfSpan(rtf,p,stamp+2,LC_DIM); p = stamp+2; }
    const wchar_t *pid = wcsstr(p,L" (PID:"), *dest = wcsstr(p,L") -> "), *via = wcsstr(p,L"  via ");
    if (pid && dest && via && pid < dest && dest < via) {
        RtfSpan(rtf,p,pid,LC_GREEN);
        RtfSpan(rtf,pid,dest+5,LC_DIM);
        RtfSpan(rtf,dest+5,via,LC_ORANGE);
        RtfSpan(rtf,via,via+6,LC_DIM); p = via+6;
        const wchar_t *status = wcsstr(p,L" | status=");
        const wchar_t *proxyEnd = status ? status : end;
        int proxyColour = !wcsncmp(p,L"Direct",6) ? LC_DIM : !wcsncmp(p,L"Block",5) ? LC_RED : LC_PURPLE;
        const wchar_t *protocol = wcsstr(p,L"(UDP)");
        if (!protocol) protocol = wcsstr(p,L"(TCP)");
        if (protocol && protocol + 5 <= proxyEnd) {
            RtfSpan(rtf,p,protocol,proxyColour); RtfSpan(rtf,protocol,protocol+5,LC_BLUE);
            RtfSpan(rtf,protocol+5,proxyEnd,proxyColour);
        } else RtfSpan(rtf,p,proxyEnd,proxyColour);
        if (status) {
            const wchar_t *value = status+10, *rule = wcsstr(value,L" | rule=");
            RtfSpan(rtf,status,status+3,LC_DIM);
            RtfSpan(rtf,status+3,rule ? rule : end,LogStatusColour(value));
            if (rule) {
                const wchar_t *match = wcsstr(rule+8,L" | match=");
                const wchar_t *details = match ? wcsstr(match+9,L" | ") : NULL;
                BOOL isDefault = !wcsncmp(rule+8,L"R0 ",3);
                RtfSpan(rtf,rule,details ? details : end,isDefault ? LC_DIM : LC_TEAL);
                if (details) RtfSpan(rtf,details,end,LC_DIM);
            }
        }
    } else {
        if (!wcsncmp(p,L"[GUI] ",6)) { RtfSpan(rtf,p,p+6,LC_GREEN); p+=6; }
        else if (!wcsncmp(p,L"[CORE] ",7)) { RtfSpan(rtf,p,p+7,LC_PURPLE); p+=7; }
        int severity = LC_TEXT;
        if (wcsstr(p,L"ERROR") || wcsstr(p,L"FAILED") || wcsstr(p,L"failed") || wcsstr(p,L"Failed")) severity = LC_RED;
        else if (wcsstr(p,L"WARN") || wcsstr(p,L"timeout") || wcsstr(p,L"worker stopped")) severity = LC_AMBER;
        else if (!wcsncmp(p,L"[INFO]",6)) severity = LC_BLUE;
        RtfSpan(rtf,p,end,severity);
    }
}

static BOOL BuildLogRtf(LogRtf *rtf, const wchar_t *text)
{
    RtfAdd(rtf,"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fmodern Consolas;}}{\\colortbl;");
    for (int i=0; i<(int)ARRAYSIZE(g_logColors); i++) {
        char colour[64]; COLORREF c = g_logColors[i];
        snprintf(colour,sizeof(colour),"\\red%d\\green%d\\blue%d;",GetRValue(c),GetGValue(c),GetBValue(c));
        RtfAdd(rtf,colour);
    }
    RtfAdd(rtf,"}\\f0\\fs22\\uc1 ");
    wchar_t *copy = _wcsdup(text);
    if (!copy) { rtf->failed = TRUE; return FALSE; }
    wchar_t *p=copy;
    while (*p) {
        wchar_t *end=p; while (*end && *end != L'\r' && *end != L'\n') end++;
        wchar_t newline=*end; *end=0;
        RtfLogLine(rtf,p);
        if (!newline) break;
        RtfAdd(rtf,"\\par ");
        p=end+1; if (newline==L'\r' && *p==L'\n') p++;
    }
    free(copy); RtfAdd(rtf,"}");
    return !rtf->failed;
}

static DWORD CALLBACK LogRtfRead(DWORD_PTR cookie, LPBYTE buffer, LONG requested, LONG *read)
{
    LogRtf *rtf=(LogRtf*)cookie;
    size_t remaining=rtf->length-rtf->offset;
    *read=(LONG)(remaining < (size_t)requested ? remaining : (size_t)requested);
    memcpy(buffer,rtf->data+rtf->offset,(size_t)*read); rtf->offset+=(size_t)*read;
    return 0;
}

static BOOL LogIsAtBottom(HWND edit)
{
    // WM_SETTEXT can leave stale scrollbar metrics until the next layout pass.
    if (GetWindowTextLengthW(edit) == 0) return TRUE;
    POINT position; SendMessageW(edit,EM_GETSCROLLPOS,0,(LPARAM)&position);
    if (position.y == 0) {
        GETTEXTLENGTHEX info={GTL_PRECISE,1200};
        LONG length=(LONG)SendMessageW(edit,EM_GETTEXTLENGTHEX,(WPARAM)&info,0);
        POINT last; SendMessageW(edit,EM_POSFROMCHAR,(WPARAM)&last,length);
        LONG lines=(LONG)SendMessageW(edit,EM_GETLINECOUNT,0,0);
        LONG lineHeight=1;
        if (lines > 1) {
            LONG previous=(LONG)SendMessageW(edit,EM_LINEINDEX,lines-2,0);
            POINT previousPos; SendMessageW(edit,EM_POSFROMCHAR,(WPARAM)&previousPos,previous);
            if (last.y > previousPos.y) lineHeight=last.y-previousPos.y;
        }
        RECT area; SendMessageW(edit,EM_GETRECT,0,(LPARAM)&area);
        if (last.y >= area.top && last.y + lineHeight <= area.bottom) return TRUE;
    }
    SCROLLINFO scroll = {sizeof(scroll), SIF_RANGE | SIF_PAGE | SIF_POS};
    if (!GetScrollInfo(edit, SB_VERT, &scroll)) return TRUE;
    int bottom = scroll.nMax - (scroll.nPage ? (int)scroll.nPage - 1 : 0);
    if (bottom < scroll.nMin) bottom = scroll.nMin;
    // RichEdit can stop one pixel short of the Win32 inclusive scroll maximum.
    return scroll.nPos >= bottom - 1;
}

static void AppendToEdit(HWND edit, const wchar_t *text)
{
    LogRtf rtf={0};
    if (!BuildLogRtf(&rtf,text)) { free(rtf.data); return; }
    BOOL follow = LogIsAtBottom(edit);
    POINT position = {0}; CHARRANGE selection;
    SendMessageW(edit,EM_GETSCROLLPOS,0,(LPARAM)&position);
    SendMessageW(edit,EM_EXGETSEL,0,(LPARAM)&selection);
    GETTEXTLENGTHEX lengthInfo={GTL_PRECISE,1200};
    LONG length=(LONG)SendMessageW(edit,EM_GETTEXTLENGTHEX,(WPARAM)&lengthInfo,0);
    BOOL visible = (GetWindowLongPtrW(edit,GWL_STYLE) & WS_VISIBLE) != 0;
    if (visible) SendMessageW(edit,WM_SETREDRAW,FALSE,0);
    if (length > MAX_LOG_CHARS) {
        CHARRANGE range={0,length/2}; SendMessageW(edit,EM_EXSETSEL,0,(LPARAM)&range);
        SendMessageW(edit,EM_REPLACESEL,FALSE,(LPARAM)L"");
        selection.cpMin = selection.cpMin > range.cpMax ? selection.cpMin-range.cpMax : 0;
        selection.cpMax = selection.cpMax > range.cpMax ? selection.cpMax-range.cpMax : 0;
    }
    CHARRANGE append={-1,-1}; SendMessageW(edit,EM_EXSETSEL,0,(LPARAM)&append);
    EDITSTREAM stream={(DWORD_PTR)&rtf,0,LogRtfRead};
    SendMessageW(edit,EM_STREAMIN,SF_RTF | SFF_SELECTION,(LPARAM)&stream);
    SendMessageW(edit,EM_EXSETSEL,0,(LPARAM)&selection);
    // WM_SETREDRAW(TRUE) makes a hidden control visible: never apply it to the
    // inactive log tab while its background events are being appended.
    if (visible) SendMessageW(edit,WM_SETREDRAW,TRUE,0);
    if (follow) SendMessageW(edit,WM_VSCROLL,SB_BOTTOM,0);
    else SendMessageW(edit,EM_SETSCROLLPOS,0,(LPARAM)&position);
    InvalidateRect(edit,NULL,FALSE);
    free(rtf.data);
}
#endif
