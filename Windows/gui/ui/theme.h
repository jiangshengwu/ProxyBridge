// ui/theme.h - light-theme helpers for the GUI.
//
// Unity-build include: pulled into main.c after the colour macros (C_*), brush globals
// (g_br*), the UAH menu structs and the uxtheme ordinal typedefs are declared, so this
// file relies on those already being visible. Not a standalone header.
#ifndef PB_UI_THEME_H
#define PB_UI_THEME_H

static COLORREF ColourTint(COLORREF colour, int percent)
{
    return RGB((GetRValue(colour)*percent + 255*(100-percent))/100,
               (GetGValue(colour)*percent + 255*(100-percent))/100,
               (GetBValue(colour)*percent + 255*(100-percent))/100);
}

static BOOL QuickFilterSelected(int index)
{
    if (index == 0) return !g_connStore.routeFilter && !g_connStore.protoFilter;
    return index < 4 ? g_connStore.routeFilter == index : g_connStore.protoFilter == index-3;
}

static void DrawQuickFilter(const DRAWITEMSTRUCT *draw)
{
    int index = (int)draw->CtlID - IDC_QUICK_BASE;
    static const int colours[] = {LC_DIM,LC_PURPLE,LC_BLUE,LC_RED,LC_TEAL,LC_ORANGE};
    COLORREF colour = g_logColors[colours[index]];
    BOOL selected = QuickFilterSelected(index);
    BOOL hot = g_quickHot == index || (draw->itemState & ODS_SELECTED);
    COLORREF background = selected ? C_ACCENT : ColourTint(colour,hot ? 14 : 6);
    COLORREF border = selected ? C_ACCENT : ColourTint(colour,hot ? 55 : 28);
    COLORREF foreground = selected ? RGB(255,255,255) : colour;
    HDC dc=draw->hDC; int saved=SaveDC(dc);
    FillRect(dc,&draw->rcItem,g_brBg);
    HBRUSH fill=CreateSolidBrush(background); HPEN pen=CreatePen(PS_SOLID,1,border);
    SelectObject(dc,fill); SelectObject(dc,pen);
    RECT box=draw->rcItem;
    RoundRect(dc,box.left,box.top,box.right,box.bottom,10,10);
    SelectObject(dc,g_hUi ? g_hUi : GetStockObject(DEFAULT_GUI_FONT));
    SetBkMode(dc,TRANSPARENT);
    wchar_t count[16]; _snwprintf_s(count,16,_TRUNCATE,L"%d",g_quickCounts[index]);
    SIZE size; GetTextExtentPoint32W(dc,count,lstrlenW(count),&size);
    int badgeWidth=size.cx+12;
    RECT badge={box.right-8-badgeWidth,box.top+4,box.right-8,box.bottom-4};
    HBRUSH badgeBrush=CreateSolidBrush(selected ? ColourTint(C_ACCENT,72) : ColourTint(colour,16));
    SelectObject(dc,badgeBrush); SelectObject(dc,GetStockObject(NULL_PEN));
    RoundRect(dc,badge.left,badge.top,badge.right,badge.bottom,8,8);
    SetTextColor(dc,foreground);
    DrawTextW(dc,count,-1,&badge,DT_SINGLELINE | DT_CENTER | DT_VCENTER | DT_NOPREFIX);
    RECT label={box.left+9,box.top,badge.left-5,box.bottom};
    DrawTextW(dc,g_quickLabels[index],-1,&label,DT_SINGLELINE | DT_LEFT | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
    if ((draw->itemState & ODS_FOCUS) && !(draw->itemState & ODS_NOFOCUSRECT)) {
        RECT focus=box; InflateRect(&focus,-3,-3); DrawFocusRect(dc,&focus);
    }
    RestoreDC(dc,saved);
    DeleteObject(fill); DeleteObject(pen); DeleteObject(badgeBrush);
}

static LRESULT CALLBACK QuickFilterSubProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR id, DWORD_PTR ref)
{
    if (message == WM_MOUSEMOVE && g_quickHot != (int)ref) {
        int old=g_quickHot; g_quickHot=(int)ref;
        if (old >= 0) InvalidateRect(g_hQuick[old],NULL,FALSE);
        InvalidateRect(hwnd,NULL,FALSE);
        TRACKMOUSEEVENT track={sizeof(track),TME_LEAVE,hwnd,0}; TrackMouseEvent(&track);
    } else if (message == WM_MOUSELEAVE && g_quickHot == (int)ref) {
        g_quickHot=-1; InvalidateRect(hwnd,NULL,FALSE);
    } else if (message == WM_NCDESTROY) RemoveWindowSubclass(hwnd,QuickFilterSubProc,id);
    return DefSubclassProc(hwnd,message,wp,lp);
}

static void CreateThemeBrushes(void)
{
    g_brBg     = CreateSolidBrush(C_BG);
    g_brPanel  = CreateSolidBrush(C_PANEL);
    g_brTab    = CreateSolidBrush(C_TAB);
    g_brTabSel = CreateSolidBrush(C_TABSEL);
    g_brTabHot = CreateSolidBrush(C_TABHOT);
    g_brAccent = CreateSolidBrush(C_ACCENT);
    g_brMenu   = CreateSolidBrush(C_MENU);
    g_brMenuHot= CreateSolidBrush(C_MENUHOT);
}

// Paint group frames and captions with the shared palette.
static LRESULT CALLBACK GroupSubProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    if (m == WM_PAINT)
    {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        RECT rc; GetClientRect(h, &rc);
        wchar_t txt[64] = {0}; GetWindowTextW(h, txt, 64);
        FillRect(dc, &rc, g_brBg);
        HFONT f = (HFONT)SendMessageW(h, WM_GETFONT, 0, 0);
        HFONT of = f ? (HFONT)SelectObject(dc, f) : NULL;
        SIZE ts; GetTextExtentPoint32W(dc, txt, lstrlenW(txt), &ts);
        HPEN pen = CreatePen(PS_SOLID, 1, C_LINE), op = (HPEN)SelectObject(dc, pen);
        HBRUSH ob = (HBRUSH)SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, rc.left, rc.top + ts.cy / 2, rc.right - 1, rc.bottom - 1, 6, 6);
        SelectObject(dc, ob); SelectObject(dc, op); DeleteObject(pen);
        RECT tr = { rc.left + 8, rc.top, rc.left + 14 + ts.cx, rc.top + ts.cy };
        FillRect(dc, &tr, g_brBg);                       // break the frame line behind the caption
        SetBkMode(dc, TRANSPARENT); SetTextColor(dc, C_TEXT);
        TextOutW(dc, rc.left + 11, rc.top, txt, lstrlenW(txt));
        if (of) SelectObject(dc, of);
        EndPaint(h, &ps);
        return 0;
    }
    return DefSubclassProc(h, m, w, l);
}

// Apply the light native theme to each supported child control.
static BOOL CALLBACK LightThemeChild(HWND h, LPARAM lp)
{
    (void)lp;
    wchar_t cls[48]; GetClassNameW(h, cls, 48);
    if (!_wcsicmp(cls, L"Edit") || !_wcsicmp(cls, L"ComboBox"))
        SetWindowTheme(h, L"Explorer", NULL);          // light edit/combo field
    else if (!_wcsicmp(cls, L"Button"))
    {
        if ((GetWindowLongW(h, GWL_STYLE) & BS_TYPEMASK) == BS_GROUPBOX)
            SetWindowSubclass(h, GroupSubProc, 7, 0);      // owner-paint the caption/frame
        else
            SetWindowTheme(h, L"Explorer", NULL);
    }
    else if (!_wcsicmp(cls, L"ListBox"))
        SetWindowTheme(h, L"Explorer", NULL);
    else if (!_wcsicmp(cls, L"SysListView32") || !_wcsicmp(cls, WC_TABCONTROLW))
        SetWindowTheme(h, L"Explorer", NULL);
    return TRUE;
}

static void InitLightTheme(HWND hwnd)
{
    // Force light native menus/controls even when Windows uses a dark application theme.
    HMODULE ux = LoadLibraryExW(L"uxtheme.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (ux)
    {
        fnSetPreferredAppMode setMode = (fnSetPreferredAppMode)(void*)GetProcAddress(ux, MAKEINTRESOURCEA(135));
        fnAllowDarkModeForWindow allow = (fnAllowDarkModeForWindow)(void*)GetProcAddress(ux, MAKEINTRESOURCEA(133));
        fnFlushMenuThemes flush = (fnFlushMenuThemes)(void*)GetProcAddress(ux, MAKEINTRESOURCEA(136));
        if (setMode) setMode(APPMODE_FORCELIGHT);
        if (allow)   allow(hwnd, FALSE);
        if (flush)   flush();
        FreeLibrary(ux);   // ordinals were called; release our loader ref (called per dialog)
    }
    BOOL dark = FALSE;
    DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark));
    // Match every child control to the light palette.
    EnumChildWindows(hwnd, LightThemeChild, 0);
}

// Paint over the light 1px line the OS draws under the menu bar.
static void PaintMenuBottomLine(HWND hwnd)
{
    MENUBARINFO mbi; mbi.cbSize = sizeof(mbi);
    if (!GetMenuBarInfo(hwnd, OBJID_MENU, 0, &mbi)) return;
    RECT wr; GetWindowRect(hwnd, &wr);
    RECT r = mbi.rcBar; OffsetRect(&r, -wr.left, -wr.top);
    r.top = r.bottom; r.bottom += 1;
    HDC dc = GetWindowDC(hwnd);
    FillRect(dc, &r, g_brMenu);
    ReleaseDC(hwnd, dc);
}

// Shared light colouring for dialog controls (dialog procs return the brush directly).
static INT_PTR DlgCtlColor(WPARAM wp)
{
    HDC dc = (HDC)wp;
    SetTextColor(dc, C_TEXT);
    SetBkColor(dc, C_BG);
    return (INT_PTR)g_brBg;
}

// Shared colour handling for every WM_CTLCOLOR* a dialog gets. Use inside a dialog proc's
// switch for the common case; dialogs that need per-control colours handle them explicitly.
#define PB_LIGHT_CTLCOLORS                                                    \
    case WM_CTLCOLORDLG: case WM_CTLCOLOREDIT: case WM_CTLCOLORLISTBOX:      \
    case WM_CTLCOLORBTN: case WM_CTLCOLORSTATIC: return DlgCtlColor(wp)

// Subclass the tab control: light background fill + hovered-tab tracking (owner-draw needs it).
static LRESULT CALLBACK TabSubProc(HWND h, UINT m, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR ref)
{
    (void)id; (void)ref;
    switch (m)
    {
    case WM_ERASEBKGND:
    {
        RECT rc; GetClientRect(h, &rc);
        FillRect((HDC)w, &rc, g_brPanel);
        return 1;
    }
    case WM_MOUSEMOVE:
    {
        TCHITTESTINFO ht; ht.pt.x = GET_X_LPARAM(l); ht.pt.y = GET_Y_LPARAM(l); ht.flags = 0;
        int hit = TabCtrl_HitTest(h, &ht);
        if (hit != g_tabHot)
        {
            g_tabHot = hit;
            InvalidateRect(h, NULL, FALSE);
            TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, h, 0 };
            TrackMouseEvent(&tme);
        }
        break;
    }
    case WM_MOUSELEAVE:
        if (g_tabHot != -1) { g_tabHot = -1; InvalidateRect(h, NULL, FALSE); }
        break;
    }
    return DefSubclassProc(h, m, w, l);
}

#endif // PB_UI_THEME_H
