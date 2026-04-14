#define _WIN32_WINNT 0x0A00
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <dwmapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "UxTheme.lib")
#pragma comment(lib, "dwmapi.lib")

constexpr UINT_PTR kTimerFilterDebounce = 1;
constexpr UINT kFilterDebounceMs = 90;
constexpr UINT_PTR kTimerProcessRefresh = 2;
constexpr UINT kProcessRefreshMs = 2000;

// Logical layout (96 DPI); scaled at runtime via Scale().
constexpr int kBaseMargin = 10;
constexpr int kBaseLabelH = 18;
constexpr int kBaseEditH = 28;
constexpr int kBaseProcListH = 140;
constexpr int kBaseMinWindowW = 720;
constexpr int kBaseMinWindowH = 420;

enum ControlIds : int {
  IDC_INPUT = 1001,
  IDC_PROCLIST = 1002,
  IDC_RESULTLIST = 1003,
  IDC_LABEL_INPUT = 1004,
  IDC_LABEL_PROCS = 1005,
  IDC_LABEL_WINDOWS = 1006,
};

enum MenuIds : UINT {
  IDM_COPY_WINDOW_TITLE = 20001,
  IDM_COPY_CLASS_NAME = 20002,
};

constexpr UINT WM_AUTO_ENUM_IF_SINGLE = WM_APP + 64;

HWND g_hwndMain{};
HWND g_hwndInput{};
HWND g_hwndProcList{};
HWND g_hwndResultList{};

UINT g_dpi = USER_DEFAULT_SCREEN_DPI;
HFONT g_fontUi{};
bool g_window_list_monitoring{};

struct ProcessEntry {
  DWORD pid{};
  std::wstring exe_file;
};

struct ProcessGroup {
  std::wstring exe_file;
  std::vector<DWORD> pids;
};

std::vector<ProcessGroup> g_groups;
std::vector<size_t> g_filtered_indices;

std::wstring GetTrimmedInputText(HWND hEdit) {
  if (!hEdit) {
    return {};
  }
  wchar_t buf[4096]{};
  GetWindowTextW(hEdit, buf, static_cast<int>(std::size(buf)));
  std::wstring raw(buf);
  while (!raw.empty() && (raw.back() == L' ' || raw.back() == L'\t')) {
    raw.pop_back();
  }
  size_t lead = 0;
  while (lead < raw.size() && (raw[lead] == L' ' || raw[lead] == L'\t')) {
    ++lead;
  }
  return std::wstring(raw.begin() + static_cast<std::ptrdiff_t>(lead), raw.end());
}

int Scale(int logicalPx) {
  return MulDiv(logicalPx, g_dpi, USER_DEFAULT_SCREEN_DPI);
}

std::wstring MapInvariantLower(const std::wstring& s) {
  if (s.empty()) {
    return s;
  }
  int cch = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.c_str(),
                          static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr, 0);
  if (cch <= 0) {
    return s;
  }
  std::wstring out(static_cast<size_t>(cch), L'\0');
  LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.c_str(),
                static_cast<int>(s.size()), out.data(), cch, nullptr, nullptr, 0);
  return out;
}

std::wstring FileBaseName(const std::wstring& path) {
  const auto pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) {
    return path;
  }
  return path.substr(pos + 1);
}

std::wstring StripExeExtension(std::wstring name) {
  static const wchar_t kExt[] = L".exe";
  const size_t n = name.size();
  const size_t el = std::size(kExt) - 1;
  if (n > el && _wcsnicmp(name.c_str() + (n - el), kExt, el) == 0) {
    name.resize(n - el);
  }
  return name;
}

bool IsAllDecimalDigits(const std::wstring& s) {
  if (s.empty()) {
    return false;
  }
  for (wchar_t ch : s) {
    if (ch < L'0' || ch > L'9') {
      return false;
    }
  }
  return true;
}

bool BuildProcessGroups(std::vector<ProcessGroup>& out) {
  std::vector<ProcessEntry> raw;
  const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return false;
  }
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (!Process32FirstW(snap, &pe)) {
    CloseHandle(snap);
    return false;
  }
  do {
    ProcessEntry e;
    e.pid = pe.th32ProcessID;
    e.exe_file = pe.szExeFile;
    raw.push_back(std::move(e));
  } while (Process32NextW(snap, &pe));
  CloseHandle(snap);

  std::sort(raw.begin(), raw.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
    const int cmp = _wcsicmp(FileBaseName(a.exe_file).c_str(), FileBaseName(b.exe_file).c_str());
    if (cmp != 0) {
      return cmp < 0;
    }
    return a.pid < b.pid;
  });

  out.clear();
  for (const auto& e : raw) {
    const std::wstring bn = FileBaseName(e.exe_file);
    if (out.empty() ||
        _wcsicmp(FileBaseName(out.back().exe_file).c_str(), bn.c_str()) != 0) {
      ProcessGroup g;
      g.exe_file = e.exe_file;
      g.pids.push_back(e.pid);
      out.push_back(std::move(g));
    } else {
      out.back().pids.push_back(e.pid);
    }
  }
  for (auto& g : out) {
    std::sort(g.pids.begin(), g.pids.end());
    g.pids.erase(std::unique(g.pids.begin(), g.pids.end()), g.pids.end());
  }
  return true;
}

void FormatGroupListLine(const ProcessGroup& g, wchar_t* line, size_t cap) {
  const std::wstring base = FileBaseName(g.exe_file);
  std::wstring pidpart;
  for (size_t i = 0; i < g.pids.size(); ++i) {
    if (i != 0) {
      pidpart += L", ";
    }
    wchar_t n[24]{};
    swprintf_s(n, L"%lu", static_cast<unsigned long>(g.pids[i]));
    pidpart += n;
  }
  swprintf_s(line, cap, L"%s  ·  %zu 个实例  ·  %s", base.c_str(), g.pids.size(),
             pidpart.c_str());
}

bool ProcessGroupsEqual(const std::vector<ProcessGroup>& a, const std::vector<ProcessGroup>& b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (size_t i = 0; i < a.size(); ++i) {
    if (_wcsicmp(FileBaseName(a[i].exe_file).c_str(), FileBaseName(b[i].exe_file).c_str()) != 0) {
      return false;
    }
    if (a[i].pids != b[i].pids) {
      return false;
    }
  }
  return true;
}

void RebuildFilteredList(bool preserveProcListSelection, bool allowAutoEnumPost,
                         const std::wstring* restoreGroupBasenameLower = nullptr) {
  g_filtered_indices.clear();
  if (!g_hwndInput || !g_hwndProcList) {
    return;
  }

  std::wstring basenameKeyRestore;
  if (restoreGroupBasenameLower && !restoreGroupBasenameLower->empty()) {
    basenameKeyRestore = *restoreGroupBasenameLower;
  }

  size_t prevSelGroupIdx = static_cast<size_t>(-1);
  if (preserveProcListSelection && basenameKeyRestore.empty()) {
    const int lbSel = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCURSEL, 0, 0));
    if (lbSel != LB_ERR) {
      const LRESULT data =
          SendMessageW(g_hwndProcList, LB_GETITEMDATA, static_cast<WPARAM>(lbSel), 0);
      if (data != LB_ERR && data < static_cast<LRESULT>(g_groups.size())) {
        prevSelGroupIdx = static_cast<size_t>(data);
      }
    }
  }

  const std::wstring query = GetTrimmedInputText(g_hwndInput);

  if (query.empty()) {
    g_filtered_indices.reserve(g_groups.size());
    for (size_t i = 0; i < g_groups.size(); ++i) {
      g_filtered_indices.push_back(i);
    }
  } else if (IsAllDecimalDigits(query)) {
    const unsigned long long v = wcstoull(query.c_str(), nullptr, 10);
    if (v <= static_cast<unsigned long long>(0xFFFFFFFFu)) {
      const DWORD want = static_cast<DWORD>(v);
      for (size_t i = 0; i < g_groups.size(); ++i) {
        for (DWORD p : g_groups[i].pids) {
          if (p == want) {
            g_filtered_indices.push_back(i);
            break;
          }
        }
      }
    }
  } else {
    const std::wstring qlow = MapInvariantLower(query);
    for (size_t i = 0; i < g_groups.size(); ++i) {
      const std::wstring& exe = g_groups[i].exe_file;
      const std::wstring base = FileBaseName(exe);
      const std::wstring hay = MapInvariantLower(exe);
      const std::wstring hayBase = MapInvariantLower(base);
      const std::wstring hayNoExt = MapInvariantLower(StripExeExtension(base));
      if (wcsstr(hay.c_str(), qlow.c_str()) != nullptr ||
          wcsstr(hayBase.c_str(), qlow.c_str()) != nullptr ||
          wcsstr(hayNoExt.c_str(), qlow.c_str()) != nullptr) {
        g_filtered_indices.push_back(i);
      }
    }
  }

  SendMessageW(g_hwndProcList, LB_RESETCONTENT, 0, 0);
  for (size_t idx : g_filtered_indices) {
    const auto& g = g_groups[idx];
    wchar_t line[2048]{};
    FormatGroupListLine(g, line, std::size(line));
    const int pos = static_cast<int>(SendMessageW(
        g_hwndProcList, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line)));
    if (pos != LB_ERR) {
      SendMessageW(g_hwndProcList, LB_SETITEMDATA, static_cast<WPARAM>(pos),
                   static_cast<LPARAM>(idx));
    }
  }
  int newSel = 0;
  if (g_filtered_indices.empty()) {
    newSel = -1;
  } else if (!basenameKeyRestore.empty()) {
    int found = -1;
    for (int i = 0; i < static_cast<int>(g_filtered_indices.size()); ++i) {
      const size_t gi = g_filtered_indices[static_cast<size_t>(i)];
      if (MapInvariantLower(FileBaseName(g_groups[gi].exe_file)) == basenameKeyRestore) {
        found = i;
        break;
      }
    }
    newSel = found >= 0 ? found : 0;
  } else if (preserveProcListSelection && prevSelGroupIdx != static_cast<size_t>(-1)) {
    int found = -1;
    for (int i = 0; i < static_cast<int>(g_filtered_indices.size()); ++i) {
      if (g_filtered_indices[static_cast<size_t>(i)] == prevSelGroupIdx) {
        found = i;
        break;
      }
    }
    newSel = found >= 0 ? found : 0;
  }
  if (newSel < 0) {
    SendMessageW(g_hwndProcList, LB_SETCURSEL, static_cast<WPARAM>(-1), 0);
  } else {
    SendMessageW(g_hwndProcList, LB_SETCURSEL, static_cast<WPARAM>(newSel), 0);
  }

  if (allowAutoEnumPost && g_filtered_indices.size() == 1 && !query.empty() && g_hwndMain) {
    PostMessageW(g_hwndMain, WM_AUTO_ENUM_IF_SINGLE, 0, 0);
  }
}

void ScheduleFilter() {
  KillTimer(g_hwndMain, kTimerFilterDebounce);
  SetTimer(g_hwndMain, kTimerFilterDebounce, kFilterDebounceMs, nullptr);
}

void RefreshProcessGroupsIncremental() {
  std::vector<ProcessGroup> next;
  if (!BuildProcessGroups(next)) {
    return;
  }
  if (ProcessGroupsEqual(g_groups, next)) {
    return;
  }
  std::wstring selKey;
  if (g_hwndProcList && !g_groups.empty()) {
    const int lbSel = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCURSEL, 0, 0));
    if (lbSel != LB_ERR) {
      const LRESULT data =
          SendMessageW(g_hwndProcList, LB_GETITEMDATA, static_cast<WPARAM>(lbSel), 0);
      if (data != LB_ERR && data >= 0 && data < static_cast<LRESULT>(g_groups.size())) {
        selKey = MapInvariantLower(FileBaseName(g_groups[static_cast<size_t>(data)].exe_file));
      }
    }
  }
  g_groups = std::move(next);
  if (selKey.empty()) {
    RebuildFilteredList(false, false);
  } else {
    RebuildFilteredList(true, false, &selKey);
  }
}

std::wstring FormatHexPointer(HWND hwnd) {
  wchar_t b[32]{};
  swprintf_s(b, L"0x%llX",
             static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(hwnd)));
  return b;
}

std::wstring FormatHexDword(DWORD v) {
  wchar_t b[32]{};
  swprintf_s(b, L"0x%08lX", static_cast<unsigned long>(v));
  return b;
}

std::wstring FormatHexDwordPtr(DWORD_PTR v) {
  wchar_t b[32]{};
  swprintf_s(b, L"0x%llX", static_cast<unsigned long long>(v));
  return b;
}

void AppendWindowRow(HWND hwnd) {
  wchar_t className[256]{};
  GetClassNameW(hwnd, className, static_cast<int>(std::size(className)));

  const int textLen = GetWindowTextLengthW(hwnd);
  std::wstring title;
  if (textLen > 0) {
    title.resize(static_cast<size_t>(textLen) + 1);
    GetWindowTextW(hwnd, title.data(), textLen + 1);
    title.resize(static_cast<size_t>(textLen));
  }

  DWORD ownerPid = 0;
  GetWindowThreadProcessId(hwnd, &ownerPid);

  RECT rc{};
  GetWindowRect(hwnd, &rc);
  const int w = rc.right - rc.left;
  const int h = rc.bottom - rc.top;

  const LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
  const LONG_PTR exstyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
  const DWORD_PTR clsStyle = GetClassLongPtrW(hwnd, GCL_STYLE);

  LVITEMW it{};
  it.mask = LVIF_TEXT;
  it.iItem = static_cast<int>(SendMessageW(g_hwndResultList, LVM_GETITEMCOUNT, 0, 0));
  it.pszText = const_cast<LPWSTR>(L"");
  const int row = ListView_InsertItem(g_hwndResultList, &it);

  auto set = [&](int sub, const std::wstring& s) {
    ListView_SetItemText(g_hwndResultList, row, sub, const_cast<LPWSTR>(s.c_str()));
  };

  wchar_t pidBuf[24]{};
  swprintf_s(pidBuf, L"%lu", static_cast<unsigned long>(ownerPid));

  const std::wstring sHandle = FormatHexPointer(hwnd);
  const std::wstring sStyle = FormatHexDword(static_cast<DWORD>(style & 0xFFFFFFFFu));
  const std::wstring sEx = FormatHexDword(static_cast<DWORD>(exstyle & 0xFFFFFFFFu));
  const std::wstring sCls = FormatHexDwordPtr(clsStyle);

  wchar_t rectBuf[128]{};
  swprintf_s(rectBuf, L"%ld, %ld, %ld, %ld", static_cast<long>(rc.left),
             static_cast<long>(rc.top), static_cast<long>(w), static_cast<long>(h));

  set(0, sHandle);
  set(1, pidBuf);
  set(2, className);
  set(3, title);
  set(4, rectBuf);
  set(5, sStyle);
  set(6, sEx);
  set(7, sCls);
}

struct EnumTopCtx {
  DWORD pid{};
  std::vector<HWND>* out{};
};

BOOL CALLBACK EnumChildTree(HWND hwnd, LPARAM lp) {
  auto* out = reinterpret_cast<std::vector<HWND>*>(lp);
  if (IsWindowVisible(hwnd) && GetWindowTextLengthW(hwnd) > 0) {
    out->push_back(hwnd);
  }
  EnumChildWindows(hwnd, EnumChildTree, lp);
  return TRUE;
}

BOOL CALLBACK EnumTopLevel(HWND hwnd, LPARAM lp) {
  auto* ctx = reinterpret_cast<EnumTopCtx*>(lp);
  DWORD wpid = 0;
  GetWindowThreadProcessId(hwnd, &wpid);
  if (wpid == ctx->pid) {
    if (IsWindowVisible(hwnd) && GetWindowTextLengthW(hwnd) > 0) {
      ctx->out->push_back(hwnd);
    }
    EnumChildWindows(hwnd, EnumChildTree, reinterpret_cast<LPARAM>(ctx->out));
  }
  return TRUE;
}

void EnumerateProcessWindows(DWORD pid, std::vector<HWND>& out) {
  out.clear();
  EnumTopCtx ctx{pid, &out};
  EnumWindows(EnumTopLevel, reinterpret_cast<LPARAM>(&ctx));
}

void EnumerateMergedVisibleWindows(const ProcessGroup& g, std::vector<HWND>& out) {
  std::vector<HWND> acc;
  for (DWORD pid : g.pids) {
    std::vector<HWND> part;
    EnumerateProcessWindows(pid, part);
    acc.insert(acc.end(), part.begin(), part.end());
  }
  std::sort(acc.begin(), acc.end());
  acc.erase(std::unique(acc.begin(), acc.end()), acc.end());
  out = std::move(acc);
}

void ClearListViewColumns(HWND lv) {
  while (ListView_DeleteColumn(lv, 0)) {
  }
}

void SetupResultColumns() {
  ClearListViewColumns(g_hwndResultList);
  LVCOLUMNW col{};
  col.mask = LVCF_TEXT | LVCF_WIDTH;
  col.cx = Scale(118);
  col.pszText = const_cast<LPWSTR>(L"Handle");
  ListView_InsertColumn(g_hwndResultList, 0, &col);
  col.cx = Scale(72);
  col.pszText = const_cast<LPWSTR>(L"PID");
  ListView_InsertColumn(g_hwndResultList, 1, &col);
  col.cx = Scale(150);
  col.pszText = const_cast<LPWSTR>(L"Class Name");
  ListView_InsertColumn(g_hwndResultList, 2, &col);
  col.cx = Scale(200);
  col.pszText = const_cast<LPWSTR>(L"Window Title");
  ListView_InsertColumn(g_hwndResultList, 3, &col);
  col.cx = Scale(160);
  col.pszText = const_cast<LPWSTR>(L"Rect (L,T,W,H)");
  ListView_InsertColumn(g_hwndResultList, 4, &col);
  col.cx = Scale(100);
  col.pszText = const_cast<LPWSTR>(L"Style");
  ListView_InsertColumn(g_hwndResultList, 5, &col);
  col.cx = Scale(100);
  col.pszText = const_cast<LPWSTR>(L"ExStyle");
  ListView_InsertColumn(g_hwndResultList, 6, &col);
  col.cx = Scale(118);
  col.pszText = const_cast<LPWSTR>(L"Class Style");
  ListView_InsertColumn(g_hwndResultList, 7, &col);
}

void ClearResults() {
  ListView_DeleteAllItems(g_hwndResultList);
}

bool CopyStringToClipboard(const std::wstring& s) {
  if (!OpenClipboard(g_hwndMain)) {
    return false;
  }
  EmptyClipboard();
  const size_t bytes = (s.size() + 1) * sizeof(wchar_t);
  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
  if (!hMem) {
    CloseClipboard();
    return false;
  }
  void* p = GlobalLock(hMem);
  if (!p) {
    GlobalFree(hMem);
    CloseClipboard();
    return false;
  }
  std::memcpy(p, s.c_str(), bytes);
  GlobalUnlock(hMem);
  if (!SetClipboardData(CF_UNICODETEXT, hMem)) {
    GlobalFree(hMem);
    CloseClipboard();
    return false;
  }
  CloseClipboard();
  return true;
}

std::wstring GetListViewItemText(HWND lv, int row, int subItem) {
  wchar_t buf[4096]{};
  ListView_GetItemText(lv, row, subItem, buf, static_cast<int>(std::size(buf)));
  return buf;
}

void ShowResultListContextMenu(HWND owner, int screenX, int screenY) {
  if (!g_hwndResultList) {
    return;
  }
  POINT screenPt{};
  if (screenX == -1 && screenY == -1) {
    GetCursorPos(&screenPt);
  } else {
    screenPt.x = screenX;
    screenPt.y = screenY;
  }

  POINT clientPt = screenPt;
  ScreenToClient(g_hwndResultList, &clientPt);
  LVHITTESTINFO ht{};
  ht.pt = clientPt;
  ListView_HitTest(g_hwndResultList, &ht);
  int row = ht.iItem;
  if (row < 0) {
    row = ListView_GetNextItem(g_hwndResultList, static_cast<int>(-1), LVNI_SELECTED);
  }
  if (row < 0) {
    return;
  }
  ListView_SetItemState(g_hwndResultList, row, LVIS_SELECTED | LVIS_FOCUSED,
                        LVIS_SELECTED | LVIS_FOCUSED);
  ListView_SetSelectionMark(g_hwndResultList, row);

  HMENU menu = CreatePopupMenu();
  if (!menu) {
    return;
  }
  AppendMenuW(menu, MF_STRING, IDM_COPY_WINDOW_TITLE, L"复制窗体名");
  AppendMenuW(menu, MF_STRING, IDM_COPY_CLASS_NAME, L"复制 Class Name");
  const UINT cmd =
      TrackPopupMenuEx(menu, TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                       screenPt.x, screenPt.y, owner, nullptr);
  DestroyMenu(menu);

  if (cmd == IDM_COPY_WINDOW_TITLE) {
    CopyStringToClipboard(GetListViewItemText(g_hwndResultList, row, 3));
  } else if (cmd == IDM_COPY_CLASS_NAME) {
    CopyStringToClipboard(GetListViewItemText(g_hwndResultList, row, 2));
  }
}

bool TryGetSelectedProcessGroupIndex(size_t* outGidx) {
  if (!g_hwndProcList || !outGidx) {
    return false;
  }
  const int n = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCOUNT, 0, 0));
  if (n <= 0) {
    return false;
  }
  int sel = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCURSEL, 0, 0));
  if (sel == LB_ERR) {
    sel = 0;
    SendMessageW(g_hwndProcList, LB_SETCURSEL, 0, 0);
  }
  const LRESULT idxL = SendMessageW(g_hwndProcList, LB_GETITEMDATA, static_cast<WPARAM>(sel), 0);
  if (idxL == LB_ERR) {
    return false;
  }
  const size_t gidx = static_cast<size_t>(idxL);
  if (gidx >= g_groups.size()) {
    return false;
  }
  *outGidx = gidx;
  return true;
}

void FillResultListForGroupIndex(size_t gidx) {
  ClearResults();
  std::vector<HWND> hwnds;
  EnumerateMergedVisibleWindows(g_groups[gidx], hwnds);
  for (HWND hwnd : hwnds) {
    AppendWindowRow(hwnd);
  }
}

void RestoreListViewSelectionByHandleText(const std::wstring& handleHex) {
  if (!g_hwndResultList) {
    return;
  }
  const int n = ListView_GetItemCount(g_hwndResultList);
  if (n <= 0) {
    return;
  }
  if (!handleHex.empty()) {
    for (int i = 0; i < n; ++i) {
      if (GetListViewItemText(g_hwndResultList, i, 0) == handleHex) {
        ListView_SetItemState(g_hwndResultList, i, LVIS_SELECTED | LVIS_FOCUSED,
                              LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetSelectionMark(g_hwndResultList, i);
        ListView_EnsureVisible(g_hwndResultList, i, FALSE);
        return;
      }
    }
  }
  ListView_SetItemState(g_hwndResultList, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
  ListView_SetSelectionMark(g_hwndResultList, 0);
  ListView_EnsureVisible(g_hwndResultList, 0, FALSE);
}

void RefreshEnumeratedWindowsPeriodic() {
  if (!g_hwndResultList || !g_hwndProcList) {
    return;
  }
  if (!g_window_list_monitoring) {
    return;
  }

  const int selRow = ListView_GetNextItem(g_hwndResultList, static_cast<int>(-1), LVNI_SELECTED);
  std::wstring savedHandle;
  if (selRow >= 0) {
    savedHandle = GetListViewItemText(g_hwndResultList, selRow, 0);
  }

  size_t gidx = 0;
  if (!TryGetSelectedProcessGroupIndex(&gidx)) {
    ClearResults();
    return;
  }
  FillResultListForGroupIndex(gidx);
  RestoreListViewSelectionByHandleText(savedHandle);
}

void ExecuteEnumerateSelectedProcess() {
  if (!g_hwndProcList || !g_hwndResultList) {
    return;
  }
  size_t gidx = 0;
  if (!TryGetSelectedProcessGroupIndex(&gidx)) {
    ClearResults();
    g_window_list_monitoring = false;
    return;
  }
  g_window_list_monitoring = true;
  FillResultListForGroupIndex(gidx);
}

void TryTabComplete() {
  if (g_filtered_indices.size() != 1) {
    return;
  }
  const ProcessGroup& g = g_groups[g_filtered_indices[0]];
  const std::wstring base = StripExeExtension(FileBaseName(g.exe_file));
  SetWindowTextW(g_hwndInput, base.c_str());
  SendMessageW(g_hwndInput, EM_SETSEL, static_cast<WPARAM>(base.size()),
               static_cast<LPARAM>(base.size()));
  RebuildFilteredList(false, true);
}

void MoveProcSelection(int delta) {
  const int n = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCOUNT, 0, 0));
  if (n <= 0) {
    return;
  }
  int sel = static_cast<int>(SendMessageW(g_hwndProcList, LB_GETCURSEL, 0, 0));
  if (sel == LB_ERR) {
    sel = 0;
  }
  sel += delta;
  if (sel < 0) {
    sel = 0;
  }
  if (sel >= n) {
    sel = n - 1;
  }
  SendMessageW(g_hwndProcList, LB_SETCURSEL, static_cast<WPARAM>(sel), 0);
}

LRESULT CALLBACK InputSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                   UINT_PTR, DWORD_PTR) {
  if (msg == WM_SETFOCUS) {
    const LRESULT r = DefSubclassProc(hwnd, msg, wParam, lParam);
    SendMessageW(hwnd, EM_SETSEL, 0, static_cast<LPARAM>(-1));
    return r;
  }
  if (msg == WM_CHAR) {
    const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    if (ctrl && (wParam == 1 || wParam == 0x01)) {
      SendMessageW(hwnd, EM_SETSEL, 0, static_cast<LPARAM>(-1));
      return 0;
    }
  }
  if (msg == WM_KEYDOWN) {
    const bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
    if (ctrl && wParam == 0x41) {
      SendMessageW(hwnd, EM_SETSEL, 0, static_cast<LPARAM>(-1));
      return 0;
    }
    if (ctrl && wParam == VK_BACK) {
      SetWindowTextW(hwnd, L"");
      return 0;
    }
    if (wParam == VK_RETURN) {
      ExecuteEnumerateSelectedProcess();
      return 0;
    }
    if (wParam == VK_TAB && g_filtered_indices.size() == 1) {
      TryTabComplete();
      return 0;
    }
    if (wParam == VK_UP) {
      MoveProcSelection(-1);
      return 0;
    }
    if (wParam == VK_DOWN) {
      MoveProcSelection(1);
      return 0;
    }
  }
  return DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK ProcListSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                      UINT_PTR, DWORD_PTR) {
  if (msg == WM_KEYDOWN && wParam == VK_RETURN) {
    ExecuteEnumerateSelectedProcess();
    return 0;
  }
  return DefSubclassProc(hwnd, msg, wParam, lParam);
}

void ApplyFontToChildren() {
  if (!g_hwndMain || !g_fontUi) {
    return;
  }
  const LPARAM font = reinterpret_cast<LPARAM>(g_fontUi);
  EnumChildWindows(
      g_hwndMain,
      [](HWND h, LPARAM lp) -> BOOL {
        SendMessageW(h, WM_SETFONT, static_cast<WPARAM>(lp), MAKELPARAM(TRUE, 0));
        return TRUE;
      },
      font);
}

void RecreateUiFont() {
  if (g_fontUi) {
    DeleteObject(g_fontUi);
    g_fontUi = nullptr;
  }
  const int px = -MulDiv(10, g_dpi, 72);
  g_fontUi = CreateFontW(px, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                         CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                         L"Segoe UI Variable Text");
  if (!g_fontUi) {
    g_fontUi = CreateFontW(px, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                           L"Segoe UI");
  }
}

void ApplyModernChrome(HWND hwnd) {
  BOOL dark = FALSE;
  DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
  const DWORD corner = static_cast<DWORD>(DWMWCP_ROUND);
  DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corner, sizeof(corner));
}

void LayoutChildren(int clientW, int clientH) {
  const int margin = Scale(kBaseMargin);
  const int labelH = Scale(kBaseLabelH);
  const int editH = Scale(kBaseEditH);
  const int procListH = Scale(kBaseProcListH);
  int y = margin;

  HWND hLabelIn = GetDlgItem(g_hwndMain, IDC_LABEL_INPUT);
  HWND hLabelP = GetDlgItem(g_hwndMain, IDC_LABEL_PROCS);
  HWND hLabelW = GetDlgItem(g_hwndMain, IDC_LABEL_WINDOWS);

  MoveWindow(hLabelIn, margin, y, clientW - 2 * margin, labelH, TRUE);
  y += labelH + Scale(4);
  MoveWindow(g_hwndInput, margin, y, clientW - 2 * margin, editH, TRUE);
  y += editH + Scale(8);

  MoveWindow(hLabelP, margin, y, clientW - 2 * margin, labelH, TRUE);
  y += labelH + Scale(4);
  MoveWindow(g_hwndProcList, margin, y, clientW - 2 * margin, procListH, TRUE);
  y += procListH + Scale(8);

  MoveWindow(hLabelW, margin, y, clientW - 2 * margin, labelH, TRUE);
  y += labelH + Scale(4);
  const int rest = (std::max)(Scale(80), clientH - y - margin);
  MoveWindow(g_hwndResultList, margin, y, clientW - 2 * margin, rest, TRUE);
}

void OnDpiChanged(HWND hwnd, RECT* suggested) {
  if (suggested) {
    SetWindowPos(hwnd, nullptr, suggested->left, suggested->top,
                 suggested->right - suggested->left, suggested->bottom - suggested->top,
                 SWP_NOZORDER | SWP_NOACTIVATE);
  }
  g_dpi = GetDpiForWindow(hwnd);
  RecreateUiFont();
  ApplyFontToChildren();
  RECT rc{};
  GetClientRect(hwnd, &rc);
  LayoutChildren(rc.right - rc.left, rc.bottom - rc.top);
  if (g_hwndResultList) {
    ListView_DeleteAllItems(g_hwndResultList);
    SetupResultColumns();
  }
  InvalidateRect(hwnd, nullptr, TRUE);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
  switch (msg) {
    case WM_CREATE: {
      g_hwndMain = hwnd;
      g_dpi = GetDpiForWindow(hwnd);
      RecreateUiFont();

      INITCOMMONCONTROLSEX icc{};
      icc.dwSize = sizeof(icc);
      icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES;
      InitCommonControlsEx(&icc);

      ApplyModernChrome(hwnd);

      CreateWindowExW(0, L"STATIC", L"进程名或 PID",
                      WS_CHILD | WS_VISIBLE, 10, 10, 400, 18, hwnd,
                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LABEL_INPUT)),
                      GetModuleHandleW(nullptr), nullptr);

      g_hwndInput = CreateWindowExW(
          WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
          10, 32, 200, 24, hwnd,
          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_INPUT)),
          GetModuleHandleW(nullptr), nullptr);
      SetWindowSubclass(g_hwndInput, InputSubclassProc, 1, 0);

      CreateWindowExW(0, L"STATIC", L"↑/↓ 选择 · Enter 枚举可见窗体 · 同名进程已合并",
                      WS_CHILD | WS_VISIBLE, 10, 64, 500, 18, hwnd,
                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LABEL_PROCS)),
                      GetModuleHandleW(nullptr), nullptr);

      g_hwndProcList =
          CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                          WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_TABSTOP | LBS_NOTIFY |
                              LBS_NOINTEGRALHEIGHT,
                          10, 86, 200, Scale(kBaseProcListH), hwnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_PROCLIST)),
                          GetModuleHandleW(nullptr), nullptr);
      SetWindowSubclass(g_hwndProcList, ProcListSubclassProc, 2, 0);
      SetWindowTheme(g_hwndProcList, L"Explorer", nullptr);

      CreateWindowExW(0, L"STATIC", L"可见窗体", WS_CHILD | WS_VISIBLE, 10, 210,
                      300, 18, hwnd,
                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_LABEL_WINDOWS)),
                      GetModuleHandleW(nullptr), nullptr);

      g_hwndResultList =
          CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                          WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL |
                              LVS_SHOWSELALWAYS,
                          10, 232, 400, 200, hwnd,
                          reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_RESULTLIST)),
                          GetModuleHandleW(nullptr), nullptr);
      ListView_SetExtendedListViewStyle(
          g_hwndResultList, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
      SetWindowTheme(g_hwndResultList, L"Explorer", nullptr);

      ApplyFontToChildren();
      SetupResultColumns();

      BuildProcessGroups(g_groups);
      RebuildFilteredList(false, true);
      SetTimer(hwnd, kTimerProcessRefresh, kProcessRefreshMs, nullptr);
      SetFocus(g_hwndInput);
      return 0;
    }
    case WM_SIZE: {
      const int cw = GET_X_LPARAM(lParam);
      const int ch = GET_Y_LPARAM(lParam);
      if (cw > 0 && ch > 0) {
        LayoutChildren(cw, ch);
      }
      return 0;
    }
    case WM_DPICHANGED: {
      auto* r = reinterpret_cast<RECT*>(lParam);
      OnDpiChanged(hwnd, r);
      return 0;
    }
    case WM_CTLCOLORSTATIC: {
      const HDC hdc = reinterpret_cast<HDC>(wParam);
      SetBkMode(hdc, TRANSPARENT);
      SetTextColor(hdc, RGB(80, 80, 90));
      return reinterpret_cast<LRESULT>(GetSysColorBrush(COLOR_WINDOW));
    }
    case WM_CTLCOLOREDIT: {
      const HDC hdc = reinterpret_cast<HDC>(wParam);
      SetBkColor(hdc, RGB(252, 252, 254));
      SetTextColor(hdc, RGB(28, 28, 32));
      static HBRUSH brEdit = CreateSolidBrush(RGB(252, 252, 254));
      return reinterpret_cast<LRESULT>(brEdit);
    }
    case WM_CTLCOLORLISTBOX: {
      const HDC hdc = reinterpret_cast<HDC>(wParam);
      SetBkColor(hdc, RGB(248, 249, 252));
      SetTextColor(hdc, RGB(28, 28, 32));
      static HBRUSH brLb = CreateSolidBrush(RGB(248, 249, 252));
      return reinterpret_cast<LRESULT>(brLb);
    }
    case WM_NOTIFY: {
      const auto* nh = reinterpret_cast<const NMHDR*>(lParam);
      if (nh->hwndFrom == g_hwndResultList && nh->code == NM_RCLICK) {
        const auto* nm = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
        POINT pt = nm->ptAction;
        ClientToScreen(g_hwndResultList, &pt);
        ShowResultListContextMenu(hwnd, pt.x, pt.y);
        return TRUE;
      }
      return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_CONTEXTMENU: {
      if (reinterpret_cast<HWND>(wParam) == g_hwndResultList) {
        const int x = GET_X_LPARAM(lParam);
        const int y = GET_Y_LPARAM(lParam);
        ShowResultListContextMenu(hwnd, x, y);
        return 0;
      }
      return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_TIMER:
      if (wParam == kTimerFilterDebounce) {
        KillTimer(hwnd, kTimerFilterDebounce);
        RebuildFilteredList(false, true);
        return 0;
      }
      if (wParam == kTimerProcessRefresh) {
        RefreshProcessGroupsIncremental();
        RefreshEnumeratedWindowsPeriodic();
        return 0;
      }
      return 0;
    case WM_AUTO_ENUM_IF_SINGLE:
      if (g_filtered_indices.size() == 1) {
        ExecuteEnumerateSelectedProcess();
      }
      return 0;
    case WM_COMMAND: {
      const int id = LOWORD(wParam);
      const int code = HIWORD(wParam);
      if (id == IDC_INPUT && code == EN_CHANGE) {
        ScheduleFilter();
        return 0;
      }
      if (id == IDC_PROCLIST && code == LBN_DBLCLK) {
        ExecuteEnumerateSelectedProcess();
        return 0;
      }
      return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_GETMINMAXINFO: {
      auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
      mmi->ptMinTrackSize.x = Scale(kBaseMinWindowW);
      mmi->ptMinTrackSize.y = Scale(kBaseMinWindowH);
      return 0;
    }
    case WM_DESTROY:
      KillTimer(hwnd, kTimerProcessRefresh);
      RemoveWindowSubclass(g_hwndInput, InputSubclassProc, 1);
      RemoveWindowSubclass(g_hwndProcList, ProcListSubclassProc, 2);
      if (g_fontUi) {
        DeleteObject(g_fontUi);
        g_fontUi = nullptr;
      }
      PostQuitMessage(0);
      return 0;
    default:
      return DefWindowProcW(hwnd, msg, wParam, lParam);
  }
}

void RegisterMainWindowClass(HINSTANCE inst) {
  WNDCLASSW wc{};
  wc.lpfnWndProc = MainWndProc;
  wc.hInstance = inst;
  wc.lpszClassName = L"WindowViewMain";
  wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
  wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
  RegisterClassW(&wc);
}

void CenterWindowOnWorkArea(HWND hwnd) {
  RECT wr{};
  if (!GetWindowRect(hwnd, &wr)) {
    return;
  }
  const int ww = wr.right - wr.left;
  const int wh = wr.bottom - wr.top;
  RECT wa{};
  SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
  const int x = wa.left + ((wa.right - wa.left) - ww) / 2;
  const int y = wa.top + ((wa.bottom - wa.top) - wh) / 2;
  SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

int APIENTRY wWinMain(HINSTANCE inst, HINSTANCE, LPWSTR, int show) {
  SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
  g_dpi = GetDpiForSystem();
  RegisterMainWindowClass(inst);
  HWND hwnd = CreateWindowExW(
      0, L"WindowViewMain", L"Window View",
      WS_OVERLAPPEDWINDOW | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, Scale(980), Scale(640),
      nullptr, nullptr, inst, nullptr);
  if (!hwnd) {
    return 1;
  }
  CenterWindowOnWorkArea(hwnd);
  ShowWindow(hwnd, show);
  UpdateWindow(hwnd);

  MSG msg{};
  while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
    TranslateMessage(&msg);
    DispatchMessageW(&msg);
  }
  return static_cast<int>(msg.wParam);
}
