/* =============================================================================
 * pwdvault Web UI —— app.js（T10 主界面 + T11 待整理/设置/健康检查 + SSE）
 *
 * 三条硬纪律（DESIGN §11.4，违反即返工）
 *   1. 服务端来的任何字符串只走 textContent / 属性赋值，绝不拼进 innerHTML。
 *      本文件 **一次 innerHTML 都没用**（连静态模板也没有），所有节点 createElement。
 *   2. 没有 eval / new Function / 内联事件属性。事件全部 addEventListener + 事件委托。
 *   3. 没有内联 <script>/<style>：脚本在文件里，样式在 app.css 里。
 *
 * 后端契约见 T10 任务说明（已冻结）。业务接口可能还没上线，所有调用点都能在 404 时
 * 降级成「此功能暂未就绪」，不留白屏、不弹错误框。
 * ========================================================================== */
(function () {
  "use strict";

  /* =========================================================== 0. 常量与工具 */
  const THEME_KEY = "pv.theme";
  const THEME_VALUES = ["system", "light", "dark"];
  const REVEAL_SECONDS = 15;
  const LIST_PAGE = 200;      // 每次向服务端要多少条
  const LIST_CHUNK = 80;      // 每次向 DOM 里塞多少行
  const SEARCH_DEBOUNCE_MS = 180;
  const POLL_MS = 3000;

  //: 服务端用这两个占位符表达「空」与「已掩码」，前端不能把它们当值写回去
  const EMPTY_MASK = "（空）";
  const MASK_ONLY = /^[•·]+$/;

  const FIELD_LABELS = {
    title: "标题",
    username: "账号",
    password: "密码",
    totp: "动态码",
    url: "网址",
    notes: "备注",
    tags: "标签",
  };

  const EMPTY_TEXT = {
    listEmpty: "密码库还是空的。点左边「+ 新建记录」，或者把 TXT 拖进「待整理」让我帮你整理。",
    searchEmpty: "没有匹配的记录。换个关键词，或者清空搜索框。",
    viewEmpty: "这个视图里没有记录。",
    detailEmpty: "从左边选一条记录，这里会显示账号、密码、备注和自定义字段。",
    tagsEmpty: "还没有标签",
    batchEmpty: "暂无批次",
    stagingEmpty: "这里会放需要你确认的整理结果。把文件拖进来试试。",
  };

  function $(id) {
    return document.getElementById(id);
  }

  /**
   * 建节点。只接受文本 / 属性 / 事件，故意不提供 html 选项 —— 堵住注入路径。
   * @param {string} tag
   * @param {{cls?:string,text?:string,attrs?:Object,data?:Object,on?:Object,props?:Object}} opts
   * @param {Array<Node|string|null|undefined>} [kids]
   * @returns {HTMLElement}
   */
  function el(tag, opts, kids) {
    const node = document.createElement(tag);
    const o = opts || {};
    if (o.cls) node.className = o.cls;
    if (o.text !== undefined && o.text !== null) node.textContent = String(o.text);
    if (o.attrs) {
      Object.keys(o.attrs).forEach((key) => {
        const value = o.attrs[key];
        if (value === null || value === undefined || value === false) return;
        if (value === true) node.setAttribute(key, "");
        else node.setAttribute(key, String(value));
      });
    }
    if (o.data) {
      Object.keys(o.data).forEach((key) => {
        const value = o.data[key];
        if (value === null || value === undefined) return;
        node.dataset[key] = String(value);
      });
    }
    if (o.props) {
      Object.keys(o.props).forEach((key) => {
        node[key] = o.props[key];
      });
    }
    if (o.on) {
      Object.keys(o.on).forEach((key) => {
        node.addEventListener(key, o.on[key]);
      });
    }
    if (kids) {
      kids.forEach((kid) => {
        if (kid === null || kid === undefined) return;
        node.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
      });
    }
    return node;
  }

  function clearNode(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setText(id, text) {
    const node = $(id);
    if (node) node.textContent = text === null || text === undefined ? "" : String(text);
  }

  function toggleHidden(id, hidden) {
    const node = $(id);
    if (node) node.hidden = !!hidden;
  }

  function fmtRelative(seconds) {
    const value = Number(seconds);
    if (!isFinite(value)) return "未知";
    if (value < 5) return "刚刚";
    if (value < 60) return Math.round(value) + " 秒前";
    if (value < 3600) return Math.round(value / 60) + " 分钟前";
    if (value < 86400) return Math.round(value / 3600) + " 小时前";
    return Math.round(value / 86400) + " 天前";
  }

  function fmtMinutes(seconds) {
    const value = Number(seconds);
    if (!isFinite(value) || value <= 0) return "永不自动锁定";
    const minutes = Math.round(value / 60);
    if (minutes < 1) return "少于 1 分钟";
    if (minutes < 60) return minutes + " 分钟";
    return Math.floor(minutes / 60) + " 小时 " + (minutes % 60) + " 分";
  }

  function fmtDate(value) {
    if (!value) return "";
    const text = String(value);
    // 服务端给 ISO8601；直接切字符串避免时区二次换算带来的偏移
    const match = text.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})/);
    if (match) return match[1] + "-" + match[2] + "-" + match[3] + " " + match[4] + ":" + match[5];
    return text;
  }

  /** 只放行 http/https，挡住 `javascript:` 这类 URL 注入。 */
  function safeHref(raw) {
    const text = String(raw || "").trim();
    if (!/^https?:\/\//i.test(text)) return "";
    return text;
  }

  function csvToList(raw) {
    return String(raw || "")
      .split(/[,，;；\s]+/)
      .map((item) => item.trim())
      .filter((item) => item.length > 0);
  }

  function listToCsv(list) {
    if (!Array.isArray(list)) return "";
    return list.join(", ");
  }

  function debounce(fn, ms) {
    let timer = 0;
    return function () {
      const args = arguments;
      const self = this;
      window.clearTimeout(timer);
      timer = window.setTimeout(() => fn.apply(self, args), ms);
    };
  }

  function toArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function num(value, fallback) {
    const parsed = Number(value);
    return isFinite(parsed) ? parsed : fallback;
  }

  /* =============================================================== 1. 主题 */
  /* 本段在 head 里同步执行（app.js 是同步脚本），所以 body 还没渲染就把
     data-theme 定好了 —— 深色用户不会看到白闪（DESIGN §11.1）。 */
  const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");

  function readThemePref() {
    try {
      const stored = localStorage.getItem(THEME_KEY);
      if (THEME_VALUES.indexOf(stored) >= 0) return stored;
    } catch (exc) {
      /* localStorage 被禁用时按系统走 */
    }
    return "system";
  }

  function effectiveTheme(pref) {
    if (pref === "light" || pref === "dark") return pref;
    return darkQuery.matches ? "dark" : "light";
  }

  function applyTheme(pref) {
    document.documentElement.dataset.theme = effectiveTheme(pref);
  }

  const initialPref = readThemePref();
  applyTheme(initialPref);

  /* =========================================================== 2. 运行期状态 */
  const state = {
    session: null,
    revision: 0,
    records: [],
    visible: [],
    rendered: 0,
    total: 0,
    countAll: 0,
    tags: [],
    query: "",
    view: "all",
    tag: "",
    selectedId: null,
    detail: null,
    detailToken: 0,
    reveal: null,           // {field, value, deadline}
    revealTimer: 0,
    themePref: initialPref,
    page: "records",
    listLoading: false,
    listError: "",
    missing: {},            // 404 降级的接口标记
    staging: {
      count: 0,
      batches: [],
      currentId: null,
      batch: null,
      items: [],
      originals: {},        // index -> {password, totp, fields}（服务端给的掩码原样）
      mode: "skip",         // 重复策略：skip|overwrite|append（服务端是批次级，不是条目级）
      saveTimers: {},
      editorHeld: false,
      touched: false,       // 用户正在改表单：阻断 SSE 触发的重渲染，别把输入框清掉
      busy: false,
    },
    health: null,
    healthError: "",
    mcpConfig: undefined,   // undefined=还没拉；null=拉过但失败（降级显示）；object=缓存
    lockDeadline: 0,
    lastCopy: null,
    sse: null,
    pollTimer: 0,
    sideCollapsed: false,
    toastSeq: 0,
  };

  /* ============================================================== 3. API 层 */
  class ApiError extends Error {
    constructor(status, code, message, hint, data) {
      super(message || "请求没有成功。");
      this.name = "ApiError";
      this.status = Number(status) || 0;
      this.code = String(code || "unknown");
      this.hint = hint ? String(hint) : "";
      // 保留原始响应体：409 的 {conflict:{...}} 要靠它做三选一
      this.data = data && typeof data === "object" ? data : null;
    }

    /** 409 冲突详情（契约：{record_id, kind, mine, theirs}）。 */
    get conflict() {
      return this.data && this.data.conflict ? this.data.conflict : null;
    }
  }

  function defaultHttpMessage(status) {
    switch (status) {
      case 0: return "连不上本地服务。";
      case 400: return "这个请求被拒绝了。";
      case 401: return "会话失效了，请刷新页面或重新解锁。";
      case 404: return "这个功能还没就绪。";
      case 409: return "记录刚被另一个窗口改过。";
      case 413: return "文件太大了。";
      case 503: return "另一个窗口正在写入，稍等一下再试。";
      default: return "服务返回了 " + status + "。";
    }
  }

  async function apiRequest(method, path, body, extraHeaders) {
    const headers = { Accept: "application/json" };
    Object.keys(extraHeaders || {}).forEach((key) => {
      headers[key] = extraHeaders[key];
    });
    const init = { method: method, credentials: "same-origin", headers: headers };
    if (body !== undefined && body !== null) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch(path, init);
    } catch (exc) {
      throw new ApiError(0, "network", "连不上本地服务，确认终端里的 pwdvault 还开着。", "重新打开页面会重新建立会话。");
    }
    let raw = "";
    try {
      raw = await response.text();
    } catch (exc) {
      raw = "";
    }
    let data = null;
    if (raw) {
      try {
        data = JSON.parse(raw);
      } catch (exc) {
        data = null;
      }
    }
    if (!response.ok) {
      const code = data && data.code ? String(data.code) : "http_" + response.status;
      const message = data && data.message ? String(data.message) : defaultHttpMessage(response.status);
      const hint = data && data.hint ? String(data.hint) : "";
      throw new ApiError(response.status, code, message, hint, data);
    }
    return data === null ? {} : data;
  }

  function apiGet(path) {
    return apiRequest("GET", path);
  }

  /** 404（接口没实现）时返回 null，让调用方降级而不是报错。 */
  async function apiOptional(path, method, body) {
    try {
      return await apiRequest(method || "GET", path, body);
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 404) return null;
      throw exc;
    }
  }

  /** 把后端错误翻成用户能读的一句话；PRD §13 里点名的场景必须逐字用原文。 */
  function describeError(exc) {
    if (!(exc instanceof ApiError)) {
      return exc && exc.message ? String(exc.message) : "出了点问题，操作没有生效。";
    }
    const byCode = {
      auth_failed: exc.message,
      locked: "密码库现在是锁着的。先打开界面解锁，或开启本机免密。",
      lock_timeout: "另一个窗口正在写入，稍等一下再试。",
      record_conflict: "这条记录刚被另一个窗口改过。",
      record_not_found: "这条记录已经不在了，可能在别的窗口删掉了。",
      staging_busy: "另一个窗口正在整理这批文件，先让那边弄完。",
      staging_not_found: "这批整理结果已经不在了。",
      invalid_record: exc.message,
      weak_password: exc.message,
      import_failed: exc.message,
      network: exc.message,
      unauthorized: "页面会话失效了，刷新一下页面。",
    };
    if (byCode[exc.code]) return byCode[exc.code];
    return exc.message || defaultHttpMessage(exc.status);
  }

  function reportError(exc, fallback) {
    const text = describeError(exc) || fallback || "操作没有生效。";
    const hint = exc instanceof ApiError ? exc.hint : "";
    toast(text, "danger", hint);
    if (exc instanceof ApiError && exc.code === "unauthorized") {
      setSync("会话失效");
    }
  }

  /* ========================================================== 4. Toast / 进度 */
  function toast(message, kind, sub) {
    const box = $("pv-toasts");
    if (!box) return;
    state.toastSeq += 1;
    const seq = state.toastSeq;
    const node = el("div", { cls: "pv-toast", data: { kind: kind || "info", show: "false", seq: seq } }, [
      el("span", { cls: "pv-toast-text", text: message }),
    ]);
    if (sub) node.appendChild(el("span", { cls: "pv-toast-sub", text: sub }));
    box.appendChild(node);
    // 最多同时 3 条，旧的先走
    while (box.children.length > 3) box.removeChild(box.firstChild);
    window.requestAnimationFrame(() => {
      node.dataset.show = "true";
    });
    window.setTimeout(() => {
      node.dataset.show = "false";
      window.setTimeout(() => {
        if (node.parentNode) node.parentNode.removeChild(node);
      }, 220);
    }, sub ? 3600 : 2600);
  }

  function progressNode() {
    let node = document.querySelector(".pv-progress");
    if (!node) {
      node = el("div", { cls: "pv-progress", attrs: { "aria-hidden": "true" } });
      document.body.appendChild(node);
    }
    return node;
  }

  function progressStart() {
    const node = progressNode();
    node.dataset.active = "true";
  }

  function progressDone() {
    const node = progressNode();
    node.dataset.active = "done";
    window.setTimeout(() => {
      node.dataset.active = "false";
    }, 260);
  }

  /* =============================================================== 5. 弹层 */
  let modalState = { open: false, onClose: null, prevFocus: null };

  function openModal(options) {
    const opts = options || {};
    const modal = $("pv-modal");
    modalState.prevFocus = document.activeElement;
    modalState.onClose = opts.onClose || null;
    modalState.open = true;
    setText("pv-modal-title", opts.title || "");
    const body = $("pv-modal-body");
    clearNode(body);
    toArray(opts.body).forEach((node) => {
      if (node) body.appendChild(node);
    });
    const foot = $("pv-modal-foot");
    clearNode(foot);
    let autofocusNode = null;
    toArray(opts.actions).forEach((action) => {
      const btn = el("button", {
        cls: "pv-btn " + (action.kind === "primary" ? "pv-btn-primary" : action.kind === "danger" ? "pv-btn-danger" : action.kind === "dangerGhost" ? "pv-btn-danger-ghost" : ""),
        text: action.label,
        attrs: { type: "button" },
        on: {
          click: () => {
            if (action.keepOpen) {
              if (action.onClick) action.onClick();
              return;
            }
            closeModal();
            if (action.onClick) action.onClick();
          },
        },
      });
      foot.appendChild(btn);
      if (action.autofocus) autofocusNode = btn;
    });
    modal.hidden = false;
    // 默认焦点给「取消」这类安全动作（DESIGN §11.3）
    window.setTimeout(() => {
      if (autofocusNode) autofocusNode.focus();
      else if (foot.firstChild) foot.firstChild.focus();
    }, 0);
  }

  function closeModal() {
    const modal = $("pv-modal");
    if (!modal || modal.hidden) return;
    modal.hidden = true;
    clearNode($("pv-modal-body"));
    clearNode($("pv-modal-foot"));
    modalState.open = false;
    const handler = modalState.onClose;
    modalState.onClose = null;
    const prev = modalState.prevFocus;
    if (prev && typeof prev.focus === "function") prev.focus();
    if (handler) handler();
  }

  function confirmDanger(options) {
    const opts = options || {};
    const body = toArray(opts.body);
    openModal({
      title: opts.title || "确认",
      body: body,
      actions: [
        { label: "取消", autofocus: true },
        { label: opts.confirmLabel || "确认", kind: "danger", onClick: opts.onConfirm },
      ],
    });
  }

  /* =============================================================== 6. 会话 */
  function agentLabel(value) {
    const text = String(value || "");
    if (text === "connected" || text === "running" || text === "ready") return "Agent 已连接";
    if (text === "disconnected" || text === "offline" || text === "stopped") return "Agent 未运行";
    return "Agent 状态未知";
  }

  function vaultDirGuess() {
    const inbox = state.session && state.session.inbox;
    if (inbox && inbox.dir) {
      return String(inbox.dir).replace(/[\\/]inbox[\\/]?$/i, "");
    }
    return "";
  }

  function renderTopbar() {
    const session = state.session || {};
    const label = session.label ? String(session.label) : "pwdvault";
    setText("pv-vault-name", label);
    const dot = $("pv-lockdot");
    if (dot) dot.dataset.locked = session.unlocked ? "false" : "true";
    setText("pv-revision", "修订 " + num(session.revision, 0));
    setText("pv-agent", agentLabel(session.agent));
    updateLockLabel();
    toggleHidden("pv-lock-now", !session.unlocked);
  }

  function updateLockLabel() {
    const session = state.session;
    const node = $("pv-lock-state");
    if (!node) return;
    if (!session || !session.unlocked) {
      node.textContent = "已锁定";
      return;
    }
    if (!state.lockDeadline) {
      node.textContent = "已解锁";
      return;
    }
    const left = Math.max(0, Math.round((state.lockDeadline - Date.now()) / 1000));
    if (left <= 0) {
      node.textContent = "已解锁 · 即将自动锁定";
      return;
    }
    const minutes = Math.floor(left / 60);
    const seconds = left % 60;
    node.textContent = "已解锁 · " + (minutes > 0 ? minutes + " 分 " : "") + seconds + " 秒后自动锁定";
  }

  function renderStatusbar() {
    const session = state.session || {};
    const inbox = session.inbox;
    if (inbox && inbox.watching) {
      setText("pv-status-inbox", "正在监听 " + String(inbox.dir || "inbox"));
    } else if (inbox && inbox.dir) {
      setText("pv-status-inbox", "inbox 监听未启动（" + String(inbox.dir) + "）");
    } else {
      setText("pv-status-inbox", "inbox 监听状态未知");
    }
    setText("pv-vault-name", session.label ? String(session.label) : "pwdvault");
  }

  function setSync(text) {
    setText("pv-status-sync", text);
  }

  function renderUnlockMeta() {
    const session = state.session || {};
    const parts = [];
    const dir = vaultDirGuess();
    if (dir) parts.push("库：" + dir);
    else if (session.label) parts.push("库：" + String(session.label));
    if (session.port) parts.push("127.0.0.1:" + session.port);
    setText("pv-unlock-vault", parts.length ? parts.join(" · ") : "本地密码库");
    const e = $("pv-unlock-vault");
    if (e) e.textContent = parts.length ? parts.join(" · ") : "本地密码库";

    const methods = toArray(session.methods);
    toggleHidden("pv-dpapi", methods.indexOf("dpapi") < 0);

    const errorBox = $("pv-unlock-error");
    if (session.vault_exists === false) {
      if (errorBox) {
        errorBox.hidden = false;
        errorBox.textContent = "这个位置还没有密码库。先确认启动时用的是哪个目录（PV_VAULT 环境变量或 --vault 参数）。";
      }
    } else if (errorBox && !errorBox.dataset.sticky) {
      errorBox.hidden = true;
      errorBox.textContent = "";
    }
  }

  function showUnlockError(message, hint) {
    const box = $("pv-unlock-error");
    if (!box) return;
    box.dataset.sticky = "1";
    box.hidden = false;
    box.textContent = hint ? String(message) + "\n" + String(hint) : String(message);
  }

  function clearUnlockError() {
    const box = $("pv-unlock-error");
    if (!box) return;
    delete box.dataset.sticky;
    box.hidden = true;
    box.textContent = "";
  }

  function setMode(mode) {
    const unlocked = mode === "app";
    toggleHidden("pv-unlock", unlocked);
    toggleHidden("pv-main", !unlocked);
    if (!unlocked) {
      const input = $("pv-password");
      if (input) {
        window.setTimeout(() => {
          try {
            input.focus();
            input.select();
          } catch (exc) {
            /* 忽略：某些环境不允许抢焦点 */
          }
        }, 30);
      }
    }
  }

  function applySession(payload, options) {
    const opts = options || {};
    const before = state.session;
    const wasUnlocked = before ? !!before.unlocked : false;
    state.session = payload || {};
    state.revision = num(state.session.revision, 0);
    if (state.session.unlocked && num(state.session.auto_lock_in_seconds, -1) > 0) {
      state.lockDeadline = Date.now() + num(state.session.auto_lock_in_seconds, 0) * 1000;
    } else {
      state.lockDeadline = 0;
    }
    renderTopbar();
    renderStatusbar();
    renderUnlockMeta();

    if (!state.session.unlocked) {
      state.records = [];
      state.visible = [];
      state.detail = null;
      state.selectedId = null;
      state.staging.items = [];
      setMode("unlock");
      if (wasUnlocked) {
        toast("密码库已自动锁定，重新解锁就能继续。", "warn");
        resetReveal();
      }
      return Promise.resolve();
    }

    setMode("app");
    if (!wasUnlocked || opts.force) {
      return ensureLoaded();
    }
    renderSidebarChrome();
    return Promise.resolve();
  }

  async function refreshSession(options) {
    const opts = options || {};
    try {
      const payload = await apiGet("/api/session");
      await applySession(payload, opts);
      return payload;
    } catch (exc) {
      if (!opts.silent) reportError(exc);
      throw exc;
    }
  }

  async function ensureLoaded() {
    await Promise.all([loadRecords({ reset: true }), loadTags(), refreshStagingBadge()]);
    if (state.page === "health") await loadHealth();
    if (state.page === "settings") await renderSettings();
  }

  async function lockNow() {
    try {
      const payload = await apiRequest("POST", "/api/lock", {});
      await applySession(payload);
      clearUnlockError();
      toast("已锁定。内存里的密钥已经丢掉了。");
    } catch (exc) {
      reportError(exc);
    }
  }

  async function submitUnlock(mode) {
    clearUnlockError();
    const button = mode === "dpapi" ? $("pv-dpapi") : mode === "recovery" ? $("pv-recovery-submit") : $("pv-unlock-submit");
    if (button) button.disabled = true;
    let body = {};
    if (mode === "password") {
      const input = $("pv-password");
      const value = input ? input.value : "";
      if (!value) {
        showUnlockError("先输主密码。");
        if (button) button.disabled = false;
        if (input) input.focus();
        return;
      }
      body = { password: value };
    } else if (mode === "recovery") {
      const input = $("pv-recovery");
      const value = input ? input.value.trim() : "";
      if (!value) {
        showUnlockError("先输恢复码。");
        if (button) button.disabled = false;
        if (input) input.focus();
        return;
      }
      body = { recovery_code: value };
    } else {
      body = { use_dpapi: true };
    }
    progressStart();
    try {
      const payload = await apiRequest("POST", "/api/unlock", body);
      const passwordInput = $("pv-password");
      if (passwordInput) passwordInput.value = "";
      const recoveryInput = $("pv-recovery");
      if (recoveryInput) recoveryInput.value = "";
      await applySession(payload, { force: true });
      toast("已解锁。");
    } catch (exc) {
      const hint = exc instanceof ApiError ? exc.hint : "";
      showUnlockError(describeError(exc), hint);
    } finally {
      if (button) button.disabled = false;
      progressDone();
    }
  }

  /* ============================================================ 7. 左栏渲染 */
  const VIEWS = [
    { key: "all", label: "全部" },
    { key: "recent", label: "最近使用" },
    { key: "no_password", label: "无密码" },
    { key: "totp", label: "有 TOTP" },
  ];

  function renderViews() {
    const box = $("pv-views");
    if (!box) return;
    clearNode(box);
    VIEWS.forEach((view) => {
      const active = state.view === view.key && state.page === "records";
      const countText = view.key === "all" ? (state.total ? String(state.total) : "") : "";
      const button = el("button", {
        cls: "pv-view-item",
        attrs: { type: "button", "aria-current": active ? "true" : "false" },
        data: { view: view.key },
      }, [
        el("span", { text: view.label }),
        countText ? el("span", { cls: "pv-view-count", text: countText }) : null,
      ]);
      button.addEventListener("click", () => {
        setView(view.key);
      });
      box.appendChild(button);
    });
  }

  function renderSidebarChrome() {
    renderViews();
    renderTags();
  }

  async function loadTags() {
    const data = await apiOptional("/api/tags");
    if (data === null) {
      state.missing.tags = true;
      renderTags();
      return;
    }
    state.tags = toArray(data.tags).map((item) => ({
      name: String(item && item.name !== undefined ? item.name : item),
      count: num(item && item.count, 0),
    }));
    renderTags();
  }

  function renderTags() {
    const box = $("pv-tag-list");
    if (!box) return;
    clearNode(box);
    const tags = toArray(state.tags);
    toggleHidden("pv-tag-empty", tags.length > 0 || state.missing.tags);
    if (state.missing.tags) {
      setText("pv-tag-empty", "标签列表暂未就绪");
      const hint = $("pv-tag-empty");
      if (hint) hint.hidden = false;
    }
    tags.slice(0, 60).forEach((tag) => {
      const active = state.tag && state.tag === tag.name;
      const button = el("button", {
        cls: "pv-tag-item",
        attrs: { type: "button", "aria-current": active ? "true" : "false", title: tag.name },
      }, [
        el("span", { cls: "pv-tag-name", text: tag.name }),
        el("span", { cls: "pv-view-count", text: String(tag.count) }),
      ]);
      button.addEventListener("click", () => {
        setTag(active ? "" : tag.name);
      });
      box.appendChild(button);
    });
  }

  function setView(key) {
    state.view = key;
    state.page = "records";
    setPageChrome();
    renderViews();
    renderList();
  }

  function setTag(name) {
    state.tag = name || "";
    state.page = "records";
    setPageChrome();
    renderTags();
    loadRecords({ reset: true });
  }

  function setPageChrome() {
    const pages = { staging: "pv-page-staging", health: "pv-page-health", settings: "pv-page-settings" };
    Object.keys(pages).forEach((key) => {
      toggleHidden(pages[key], state.page !== key);
    });
    toggleHidden("pv-list-pane", state.page !== "records");
    toggleHidden("pv-detail-pane", state.page !== "records");
    const map = { staging: "pv-goto-staging", health: "pv-goto-health", settings: "pv-goto-settings" };
    Object.keys(map).forEach((key) => {
      const node = $(map[key]);
      if (!node) return;
      if (state.page === key) node.setAttribute("aria-current", "page");
      else node.removeAttribute("aria-current");
    });
  }

  async function showPage(page) {
    state.page = page;
    setPageChrome();
    if (page === "staging") await loadStaging();
    if (page === "health") await loadHealth();
    if (page === "settings") await renderSettings();
    if (page === "records") renderList();
  }

  /* ============================================================== 8. 列表 */
  function visibleRecords() {
    let rows = state.records.slice();
    const query = state.query.trim().toLowerCase();
    if (query) {
      rows = rows.filter((record) => {
        const haystack = [record.title, record.username, record.url, listToCsv(record.tags)].join(" ").toLowerCase();
        return haystack.indexOf(query) >= 0;
      });
    }
    if (state.view === "recent") {
      rows.sort((a, b) => String(b.updated || "").localeCompare(String(a.updated || "")));
    } else if (state.view === "no_password") {
      rows = rows.filter((record) => !record.has_password);
    } else if (state.view === "totp") {
      rows = rows.filter((record) => record.has_totp);
    }
    return rows;
  }

  async function loadRecords(options) {
    const opts = options || {};
    if (state.listLoading) return;
    if (!state.session || !state.session.unlocked) return;
    state.listLoading = true;
    state.listError = "";
    if (opts.reset) {
      toggleHidden("pv-list-skeleton", false);
      toggleHidden("pv-list-empty", true);
    }
    const params = new URLSearchParams();
    if (state.query) params.set("q", state.query);
    if (state.tag) params.set("tag", state.tag);
    params.set("limit", String(LIST_PAGE));
    params.set("offset", String(opts.reset ? 0 : state.records.length));
    try {
      const data = await apiRequest("GET", "/api/records?" + params.toString());
      const rows = toArray(data.records);
      state.records = opts.reset ? rows : state.records.concat(rows);
      state.total = num(data.total, state.records.length);
      state.countAll = num(data.count, state.total);
      state.missing.records = false;
      renderList();
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 404) {
        state.missing.records = true;
        state.records = [];
        state.total = 0;
        renderList();
      } else if (exc instanceof ApiError && (exc.code === "locked" || exc.status === 401)) {
        await refreshSession({ silent: true });
      } else {
        state.listError = describeError(exc);
        renderList();
      }
    } finally {
      state.listLoading = false;
      toggleHidden("pv-list-skeleton", true);
    }
  }

  function renderListSummary() {
    const loaded = state.records.length;
    const total = state.total || loaded;
    let text = "共 " + total + " 条";
    if (loaded < total) text += " · 已加载 " + loaded + " 条";
    text += " · 修订 " + num(state.session && state.session.revision, 0);
    setText("pv-list-summary", text);

    const note = $("pv-list-note");
    if (!note) return;
    const filters = [];
    if (state.query) filters.push("搜索「" + state.query + "」");
    if (state.tag) filters.push("标签「" + state.tag + "」");
    if (state.view !== "all") {
      const view = VIEWS.filter((item) => item.key === state.view)[0];
      filters.push("视图「" + (view ? view.label : state.view) + "」（在已加载的 " + loaded + " 条里筛）");
    }
    if (filters.length) {
      note.hidden = false;
      note.textContent = filters.join(" · ");
    } else {
      note.hidden = true;
      note.textContent = "";
    }
  }

  function renderList() {
    const listNode = $("pv-list");
    if (!listNode) return;
    renderListSummary();
    state.visible = visibleRecords();
    state.rendered = 0;
    clearNode(listNode);

    const emptyNode = $("pv-list-empty");
    if (state.missing.records) {
      if (emptyNode) {
        emptyNode.hidden = false;
        clearNode(emptyNode);
        emptyNode.appendChild(el("p", { cls: "pv-empty-title", text: "记录列表暂未就绪" }));
        emptyNode.appendChild(el("p", { cls: "pv-empty-hint", text: "服务端的记录接口还没上线。等它就绪后刷新页面即可，界面其它部分不受影响。" }));
      }
      return;
    }
    if (state.listError) {
      if (emptyNode) {
        emptyNode.hidden = false;
        clearNode(emptyNode);
        emptyNode.appendChild(el("p", { cls: "pv-empty-title", text: state.listError }));
        const retry = el("button", { cls: "pv-btn pv-btn-sm", text: "重试", attrs: { type: "button" } });
        retry.addEventListener("click", () => loadRecords({ reset: true }));
        emptyNode.appendChild(retry);
      }
      return;
    }
    if (!state.visible.length) {
      if (emptyNode) {
        emptyNode.hidden = false;
        clearNode(emptyNode);
        const isFiltered = !!(state.query || state.tag || state.view !== "all");
        const text = isFiltered ? (state.query ? EMPTY_TEXT.searchEmpty : EMPTY_TEXT.viewEmpty) : EMPTY_TEXT.listEmpty;
        emptyNode.appendChild(el("p", { cls: "pv-empty-title", text: isFiltered ? "这里没有记录" : "密码库是空的" }));
        emptyNode.appendChild(el("p", { cls: "pv-empty-hint", text: text }));
        if (!isFiltered) {
          const create = el("button", { cls: "pv-btn pv-btn-sm", text: "+ 新建记录", attrs: { type: "button" } });
          create.addEventListener("click", () => openRecordDialog(null));
          emptyNode.appendChild(create);
        }
      }
      return;
    }
    if (emptyNode) emptyNode.hidden = true;
    renderRowChunk();
  }

  function renderRowChunk() {
    const listNode = $("pv-list");
    if (!listNode) return;
    const sentinel = listNode.querySelector(".pv-list-sentinel");
    if (sentinel) listNode.removeChild(sentinel);
    const next = state.visible.slice(state.rendered, state.rendered + LIST_CHUNK);
    next.forEach((record) => {
      listNode.appendChild(renderRow(record));
    });
    state.rendered += next.length;
    const more = state.rendered < state.visible.length || state.records.length < state.total;
    if (more) {
      const node = el("li", { cls: "pv-list-sentinel", attrs: { "aria-hidden": "true" } }, [
        el("span", { cls: "pv-meta", text: "往下滚还有…" }),
      ]);
      listNode.appendChild(node);
      observeSentinel(node);
    }
  }

  let sentinelObserver = null;

  function observeSentinel(node) {
    if (!("IntersectionObserver" in window)) {
      // 老浏览器：滚到底部自动续
      node.addEventListener("click", () => advanceList());
      return;
    }
    if (!sentinelObserver) {
      sentinelObserver = new IntersectionObserver((entries) => {
        if (entries.some((entry) => entry.isIntersecting)) advanceList();
      }, { root: $("pv-list"), rootMargin: "320px" });
    }
    sentinelObserver.observe(node);
  }

  function advanceList() {
    if (state.rendered < state.visible.length) {
      renderRowChunk();
      return;
    }
    if (state.records.length < state.total) loadRecords({ append: true });
  }

  function renderRow(record) {
    const id = String(record.id);
    const selected = state.selectedId === id;
    const row = el("li", {
      cls: "pv-row",
      attrs: {
        role: "option",
        tabindex: selected ? "0" : "-1",
        "aria-selected": selected ? "true" : "false",
        title: record.title ? String(record.title) : "(无标题)",
      },
      data: { id: id },
    });
    const subParts = [];
    if (record.username) subParts.push(String(record.username));
    else if (record.url) subParts.push(String(record.url));
    else subParts.push("没有账号");
    const main = el("div", { cls: "pv-row-main" }, [
      el("div", { cls: "pv-row-title", text: record.title ? String(record.title) : "(无标题)" }),
      el("div", { cls: "pv-row-sub", text: subParts.join(" · ") }),
    ]);
    const right = el("div", { cls: "pv-row-tags" });
    const tags = toArray(record.tags).slice(0, 2);
    tags.forEach((tag) => {
      right.appendChild(el("span", { cls: "pv-chip", text: String(tag), attrs: { title: String(tag) } }));
    });
    if (record.has_totp) right.appendChild(el("span", { cls: "pv-row-totp", text: "TOTP" }));

    const actions = el("div", { cls: "pv-row-actions" }, [
      el("button", {
        cls: "pv-btn pv-btn-sm", text: "复制密码", attrs: { type: "button", "aria-label": "复制这条记录的密码" },
        data: { action: "copy" },
      }),
      el("button", {
        cls: "pv-btn pv-btn-sm", text: "编辑", attrs: { type: "button", "aria-label": "编辑这条记录" },
        data: { action: "edit" },
      }),
    ]);

    row.appendChild(main);
    row.appendChild(right);
    row.appendChild(actions);
    return row;
  }

  function updateRowSelection() {
    const listNode = $("pv-list");
    if (!listNode) return;
    Array.prototype.forEach.call(listNode.querySelectorAll(".pv-row"), (row) => {
      const selected = row.dataset.id === state.selectedId;
      row.setAttribute("aria-selected", selected ? "true" : "false");
      row.tabIndex = selected ? 0 : -1;
    });
  }

  function focusSelectedRow() {
    const listNode = $("pv-list");
    if (!listNode) return;
    const row = listNode.querySelector('.pv-row[aria-selected="true"]');
    if (row && typeof row.focus === "function") row.focus();
  }

  function moveSelection(delta) {
    const rows = state.visible;
    if (!rows.length) return;
    let index = rows.findIndex((record) => String(record.id) === state.selectedId);
    if (index < 0) index = delta > 0 ? -1 : rows.length;
    const next = Math.min(rows.length - 1, Math.max(0, index + delta));
    const record = rows[next];
    if (!record) return;
    const id = String(record.id);
    // 目标行还没渲染进 DOM 时先把后面的块补上
    while (state.rendered <= next && state.rendered < state.visible.length) {
      renderRowChunk();
    }
    selectRecord(id, { focusList: true });
  }

  /* ============================================================== 9. 详情 */
  function resetReveal() {
    if (state.revealTimer) {
      window.clearInterval(state.revealTimer);
      state.revealTimer = 0;
    }
    state.reveal = null;
  }

  function startRevealTimer() {
    if (state.revealTimer) window.clearInterval(state.revealTimer);
    state.revealTimer = window.setInterval(() => {
      if (!state.reveal) {
        window.clearInterval(state.revealTimer);
        state.revealTimer = 0;
        return;
      }
      const left = Math.max(0, Math.round((state.reveal.deadline - Date.now()) / 1000));
      const node = document.querySelector(".pv-countdown");
      if (node) node.textContent = left > 0 ? left + "s" : "已隐藏";
      if (left <= 0) {
        const id = state.selectedId;
        resetReveal();
        if (id) selectRecord(id);
      }
    }, 1000);
  }

  async function selectRecord(id, options) {
    const opts = options || {};
    if (!id) return;
    resetReveal();
    state.selectedId = String(id);
    updateRowSelection();
    if (opts.focusList) focusSelectedRow();
    const token = ++state.detailToken;
    try {
      const data = await apiRequest("GET", "/api/records/" + encodeURIComponent(state.selectedId));
      if (token !== state.detailToken) return;
      state.detail = data;
      renderDetail();
      if (opts.focusTitle) focusDetailTitle();
    } catch (exc) {
      if (token !== state.detailToken) return;
      if (exc instanceof ApiError && exc.code === "locked") {
        await refreshSession({ silent: true });
        return;
      }
      state.detail = null;
      renderDetailError(describeError(exc));
    }
  }

  function focusDetailTitle() {
    const title = $("pv-detail-title");
    if (title) title.focus();
  }

  function fieldRow(key, valueNode, actions) {
    return el("div", { cls: "pv-fieldrow" }, [
      el("div", { cls: "pv-fieldrow-key", text: key }),
      valueNode,
      el("div", { cls: "pv-fieldrow-actions" }, toArray(actions)),
    ]);
  }

  function maskedNode(text) {
    return el("span", { cls: "pv-masked", text: text || "••••••••" });
  }

  function renderDetail() {
    const detail = state.detail;
    toggleHidden("pv-detail", !detail);
    toggleHidden("pv-detail-empty", !!detail);
    if (!detail) return;
    if (!state.selectedId) state.selectedId = String(detail.id);

    setText("pv-detail-title", detail.title ? String(detail.title) : "(无标题)");

    const fields = $("pv-detail-fields");
    clearNode(fields);

    // 账号
    fields.appendChild(fieldRow("账号", el("div", {
      cls: "pv-fieldrow-val" + (detail.username ? "" : " is-empty"),
      text: detail.username ? String(detail.username) : "没有填写",
    }), [
      detail.username ? el("button", {
        cls: "pv-link-btn", text: "复制", attrs: { type: "button", "aria-label": "复制账号" },
        on: { click: () => copyField(detail.id, "username") },
      }) : null,
    ]));

    // 密码
    const reveal = state.reveal && state.reveal.field === "password" ? state.reveal : null;
    const passwordValue = reveal
      ? el("div", { cls: "pv-fieldrow-val pv-mono", text: reveal.value })
      : el("div", { cls: "pv-fieldrow-val" }, [maskedNode(detail.has_password === false ? "" : "••••••••")]);
    if (detail.has_password === false && !reveal) {
      passwordValue.className = "pv-fieldrow-val is-empty";
      clearNode(passwordValue);
      passwordValue.appendChild(document.createTextNode("没有保存密码"));
    }
    const passwordActions = [];
    if (detail.has_password !== false) {
      const countdown = el("span", { cls: "pv-countdown", text: "" });
      if (reveal) {
        const left = Math.max(0, Math.round((reveal.deadline - Date.now()) / 1000));
        countdown.textContent = left + "s";
      }
      passwordActions.push(countdown);
      passwordActions.push(el("button", {
        cls: "pv-link-btn",
        text: reveal ? "隐藏" : "显示",
        attrs: { type: "button", "aria-label": reveal ? "立即隐藏密码" : "显示密码，15 秒后自动隐藏" },
        on: {
          click: () => {
            if (reveal) {
              const id = state.selectedId;
              resetReveal();
              if (id) selectRecord(id);
            } else {
              revealField("password");
            }
          },
        },
      }));
      passwordActions.push(el("button", {
        cls: "pv-link-btn", text: "复制", attrs: { type: "button", "aria-label": "复制密码" },
        on: { click: () => copyField(detail.id, "password") },
      }));
    }
    fields.appendChild(fieldRow("密码", passwordValue, passwordActions));

    // 动态码
    if (detail.has_totp) {
      const totpReveal = state.reveal && state.reveal.field === "totp" ? state.reveal : null;
      const totpNode = totpReveal
        ? el("div", { cls: "pv-fieldrow-val pv-mono", text: totpReveal.value })
        : el("div", { cls: "pv-fieldrow-val" }, [maskedNode("••••••")]);
      const totpActions = [];
      if (totpReveal) {
        const left = Math.max(0, Math.round((totpReveal.deadline - Date.now()) / 1000));
        totpActions.push(el("span", { cls: "pv-countdown", text: left + "s" }));
      }
      totpActions.push(el("button", {
        cls: "pv-link-btn",
        text: totpReveal ? "隐藏" : "查看",
        attrs: { type: "button" },
        on: {
          click: () => {
            if (totpReveal) {
              const id = state.selectedId;
              resetReveal();
              if (id) selectRecord(id);
            } else {
              revealField("totp");
            }
          },
        },
      }));
      fields.appendChild(fieldRow("动态码", totpNode, totpActions));
    }

    // 网址
    if (detail.url) {
      const href = safeHref(detail.url);
      const urlNode = href
        ? el("a", { cls: "pv-fieldrow-val", text: String(detail.url), attrs: { href: href, target: "_blank", rel: "noreferrer noopener" } })
        : el("div", { cls: "pv-fieldrow-val", text: String(detail.url) });
      fields.appendChild(fieldRow("网址", urlNode, []));
    }

    // 标签
    if (toArray(detail.tags).length) {
      const tagBox = el("div", { cls: "pv-fieldrow-val" });
      const wrap = el("div", { cls: "pv-row-tags" });
      toArray(detail.tags).forEach((tag) => {
        wrap.appendChild(el("span", { cls: "pv-chip", text: String(tag), attrs: { title: String(tag) } }));
      });
      tagBox.appendChild(wrap);
      fields.appendChild(fieldRow("标签", tagBox, []));
    }

    // 自定义字段
    const custom = $("pv-detail-custom");
    clearNode(custom);
    const customKeys = Object.keys(detail.fields || {});
    toggleHidden("pv-detail-custom-wrap", customKeys.length === 0);
    customKeys.forEach((key) => {
      const revealHere = state.reveal && state.reveal.field === key ? state.reveal : null;
      const valueNode = revealHere
        ? el("div", { cls: "pv-fieldrow-val pv-mono", text: revealHere.value })
        : el("div", { cls: "pv-fieldrow-val" }, [maskedNode(String(detail.fields[key] || "••••"))]);
      custom.appendChild(fieldRow(key, valueNode, [
        el("button", {
          cls: "pv-link-btn",
          text: revealHere ? "隐藏" : "显示",
          attrs: { type: "button", "aria-label": "显示或隐藏自定义字段 " + key },
          on: {
            click: () => {
              if (revealHere) {
                const id = state.selectedId;
                resetReveal();
                if (id) selectRecord(id);
              } else {
                revealField(key);
              }
            },
          },
        }),
      ]));
    });

    // 备注
    const notes = detail.notes ? String(detail.notes) : "";
    toggleHidden("pv-detail-notes-wrap", !notes);
    setText("pv-detail-notes", notes);

    // 页脚元信息
    const meta = $("pv-detail-meta");
    clearNode(meta);
    const metaBits = [];
    if (detail.created) metaBits.push("创建 " + fmtDate(detail.created));
    if (detail.updated) metaBits.push("更新 " + fmtDate(detail.updated));
    if (detail.pw_changed) metaBits.push("密码改动 " + fmtDate(detail.pw_changed));
    // 契约：origin 值域固定 "local" / "agent"（redact.record_origin 归一化，fail closed 到 local）。
    // 防御性：非空且不是 local 就标 —— 将来后端新增写入方（如 "import"）也不会静默不显示；
    // 字段缺失（旧服务端）时不标，宁可少显示也不要错标。
    const origin = String(detail.origin || "");
    if (origin && origin !== "local") metaBits.push("由 Agent 写入");
    metaBits.push("ID " + String(detail.id));
    metaBits.forEach((text) => meta.appendChild(el("span", { text: text })));

    // 冲突/提示条
    renderDetailBanner();

    toggleHidden("pv-open-url", !safeHref(detail.url));
    toggleHidden("pv-copy-password", detail.has_password === false);
    toggleHidden("pv-copy-username", !detail.username);
  }

  function showBanner(kind, text, actions) {
    const box = $("pv-detail-banner");
    if (!box) return;
    clearNode(box);
    if (!text) return;
    const banner = el("div", { cls: "pv-banner", data: { kind: kind || "info" } }, [
      el("p", { cls: "pv-banner-text", text: text }),
    ]);
    if (toArray(actions).length) {
      const row = el("div", { cls: "pv-banner-actions" });
      actions.forEach((action) => {
        const btn = el("button", {
          cls: "pv-btn pv-btn-sm" + (action.kind === "primary" ? " pv-btn-primary" : ""),
          text: action.label,
          attrs: { type: "button" },
        });
        btn.addEventListener("click", action.onClick);
        row.appendChild(btn);
      });
      banner.appendChild(row);
    }
    box.appendChild(banner);
  }

  function renderDetailBanner() {
    const detail = state.detail;
    if (!detail) {
      showBanner("", "");
      return;
    }
    const conflict = detail.conflict || (state.conflict && state.conflict.record_id === detail.id ? state.conflict : null);
    if (conflict) {
      showBanner("warn", "这条记录刚被另一个窗口改过。", [
        { label: "保留我的", kind: "primary", onClick: () => resolveConflict(conflict, "mine") },
        { label: "采用新的", onClick: () => resolveConflict(conflict, "theirs") },
        { label: "并排看", onClick: () => showConflictDiff(conflict) },
      ]);
      return;
    }
    if (state.reveal && state.reveal.warning) {
      showBanner("info", String(state.reveal.warning));
      return;
    }
    showBanner("", "");
  }

  function renderDetailError(message) {
    toggleHidden("pv-detail", true);
    const empty = $("pv-detail-empty");
    if (!empty) return;
    empty.hidden = false;
    clearNode(empty);
    empty.appendChild(el("p", { cls: "pv-empty-title", text: message }));
    const retry = el("button", { cls: "pv-btn pv-btn-sm", text: "重试", attrs: { type: "button" } });
    retry.addEventListener("click", () => selectRecord(state.selectedId));
    empty.appendChild(retry);
  }

  function renderDetailEmpty() {
    const empty = $("pv-detail-empty");
    if (!empty) return;
    clearNode(empty);
    empty.appendChild(el("p", { cls: "pv-empty-title", text: "没有选中记录" }));
    empty.appendChild(el("p", { cls: "pv-empty-hint", text: EMPTY_TEXT.detailEmpty }));
  }

  /* ---- 单字段明文：一次只取一个字段（DESIGN §3.9 / PRD AC4.3） */
  async function revealField(field) {
    const id = state.selectedId;
    if (!id) return;
    progressStart();
    try {
      const data = await apiRequest("GET", "/api/records/" + encodeURIComponent(id) + "?reveal=" + encodeURIComponent(field));
      const value = data && data.value !== undefined && data.value !== null ? String(data.value) : "";
      if (!data || data.revealed === false) {
        toast("服务端没有返回这个字段的明文。", "warn", "这个字段可能只能通过编辑窗口查看。");
        return;
      }
      resetReveal();
      state.reveal = {
        field: field,
        value: value,
        deadline: Date.now() + REVEAL_SECONDS * 1000,
        warning: data.warning ? String(data.warning) : "",
      };
      renderDetail();
      startRevealTimer();
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 404) {
        toast("这个字段暂时只能在编辑窗口里看。", "warn");
      } else {
        reportError(exc);
      }
    } finally {
      progressDone();
    }
  }

  /* ---- 复制：文案以 auto_clear 布尔为准，绝不无条件承诺倒计时 */
  async function copyField(id, field) {
    if (!id) return;
    progressStart();
    try {
      const data = await apiRequest("POST", "/api/records/" + encodeURIComponent(id) + "/copy", { field: field });
      const title = data && data.title ? String(data.title) : "";
      const label = FIELD_LABELS[field] || String(field);
      const prefix = title ? "已复制「" + title + "」的" + label : "已复制" + label;
      state.lastCopy = data || null;
      if (data && data.auto_clear === true) {
        const seconds = num(data.auto_clear_in, 0);
        toast(prefix + "，" + seconds + " 秒后自动清空");
      } else {
        const hint = data && data.hint ? String(data.hint) : "剪贴板会一直留着，记得自己覆盖掉。";
        toast(prefix + "（自动清空未启用）", "warn", hint);
      }
      if (state.page === "settings") renderSettings();
    } catch (exc) {
      if (exc instanceof ApiError && exc.code === "clipboard_busy") {
        toast("剪贴板被别的程序占着，请稍后再点一次。", "warn");
      } else {
        reportError(exc);
      }
    } finally {
      progressDone();
    }
  }

  /* ---- 标题 inline 编辑 */
  function startTitleEdit() {
    const detail = state.detail;
    if (!detail) return;
    const input = $("pv-detail-title-input");
    const title = $("pv-detail-title");
    if (!input || !title) return;
    input.value = detail.title ? String(detail.title) : "";
    input.hidden = false;
    title.hidden = true;
    input.focus();
    input.select();
  }

  function cancelTitleEdit() {
    const input = $("pv-detail-title-input");
    const title = $("pv-detail-title");
    if (input) {
      input.hidden = true;
      input.value = "";
    }
    if (title) title.hidden = false;
  }

  async function commitTitleEdit() {
    const input = $("pv-detail-title-input");
    const detail = state.detail;
    if (!input || !detail || input.hidden) return;
    const nextTitle = input.value.trim();
    if (!nextTitle || nextTitle === String(detail.title || "")) {
      cancelTitleEdit();
      return;
    }
    await patchRecord(detail.id, { title: nextTitle }, detail.updated, { silentSuccess: true });
    cancelTitleEdit();
  }

  async function patchRecord(id, changes, expectedUpdated, options) {
    const opts = options || {};
    // 契约：PATCH 不带 expected_updated 会 400（missing_expected_updated），那是「请求写错了」，
    // 不是冲突。这里先在本地拦一道，并把详情刷新一次，别让用户看到冲突三选一。
    if (!expectedUpdated) {
      toast("保存失败，请刷新后重试。", "warn", "没拿到这条记录的最新修订时间（updated）。");
      await selectRecord(id);
      return null;
    }
    progressStart();
    try {
      const data = await apiRequest("PATCH", "/api/records/" + encodeURIComponent(id), {
        changes: changes,
        expected_updated: expectedUpdated,
      });
      if (!opts.silentSuccess) toast("已保存。");
      state.conflict = null;
      await selectRecord(id);
      await loadRecords({ reset: true });
      return data;
    } catch (exc) {
      if (exc instanceof ApiError && exc.code === "record_conflict") {
        // 契约：409 带 {conflict:{record_id,kind,mine,theirs}}；取不到就退回通用文案
        let conflict = null;
        try {
          conflict = exc.conflict || null;
        } catch (inner) {
          conflict = null;
        }
        state.conflict = conflict || { record_id: id, kind: "update", mine: changes, theirs: null };
        showBanner("warn", "这条记录刚被另一个窗口改过。", [
          { label: "保留我的", kind: "primary", onClick: () => resolveConflict(state.conflict, "mine") },
          { label: "采用新的", onClick: () => resolveConflict(state.conflict, "theirs") },
          { label: "并排看", onClick: () => showConflictDiff(state.conflict) },
        ]);
        await selectRecord(id);
      } else if (exc instanceof ApiError && exc.code === "missing_expected_updated") {
        toast("保存失败，请刷新后重试。", "warn", exc.hint);
        await selectRecord(id);
      } else {
        reportError(exc);
      }
      throw exc;
    } finally {
      progressDone();
    }
  }

  async function resolveConflict(conflict, choice) {
    if (!conflict) return;
    const id = String(conflict.record_id || state.selectedId || "");
    if (choice === "theirs") {
      state.conflict = null;
      await selectRecord(id);
      toast("已换成最新的那份。");
      return;
    }
    state.conflict = null;
    try {
      if (conflict.mine && typeof conflict.mine === "object") {
        const fresh = await apiRequest("GET", "/api/records/" + encodeURIComponent(id));
        await apiRequest("PATCH", "/api/records/" + encodeURIComponent(id), {
          changes: conflict.mine,
          expected_updated: fresh.updated,
        });
        toast("已按你的版本保存。");
        await selectRecord(id);
        await loadRecords({ reset: true });
      } else {
        await selectRecord(id);
      }
    } catch (exc) {
      reportError(exc);
    }
  }

  function showConflictDiff(conflict) {
    const keys = Object.keys(conflict.mine || {});
    const body = [];
    if (!keys.length) {
      body.push(el("p", { cls: "pv-hint", text: "服务端没有返回具体的差异字段，只能整条采用或重试。" }));
    }
    keys.forEach((key) => {
      const mine = conflict.mine ? String(conflict.mine[key]) : "";
      const theirs = conflict.theirs && conflict.theirs[key] !== undefined ? String(conflict.theirs[key]) : "（对方没改）";
      body.push(el("div", { cls: "pv-card" }, [
        el("strong", { text: FIELD_LABELS[key] || key }),
        el("p", { cls: "pv-hint-tight", text: "我的：" + mine }),
        el("p", { cls: "pv-hint-tight", text: "新的：" + theirs }),
      ]));
    });
    openModal({
      title: "并排看两份改动",
      body: body,
      actions: [
        { label: "关掉", autofocus: true },
        { label: "保留我的", kind: "primary", onClick: () => resolveConflict(conflict, "mine") },
        { label: "采用新的", onClick: () => resolveConflict(conflict, "theirs") },
      ],
    });
  }

  /* ---- 新增 / 编辑对话框 */
  function formFieldRow(labelText, inputNode) {
    return el("div", { cls: "pv-field" }, [
      el("label", { cls: "pv-label", text: labelText, attrs: { for: inputNode.id } }),
      inputNode,
    ]);
  }

  function openRecordDialog(record) {
    const isNew = !record;
    const detail = record || {
      title: "", username: "", url: "", notes: "", totp: "", tags: [], fields: {},
    };
    const body = [];
    const titleInput = el("input", { cls: "pv-input", attrs: { id: "pv-form-title", type: "text", autocomplete: "off" }, props: { value: detail.title || "" } });
    const userInput = el("input", { cls: "pv-input", attrs: { id: "pv-form-username", type: "text", autocomplete: "off" }, props: { value: detail.username || "" } });
    const passInput = el("input", { cls: "pv-input pv-mono", attrs: { id: "pv-form-password", type: "password", autocomplete: "new-password" }, props: { value: "" } });
    const urlInput = el("input", { cls: "pv-input", attrs: { id: "pv-form-url", type: "url", autocomplete: "off", placeholder: "https://" }, props: { value: detail.url || "" } });
    const totpInput = el("input", { cls: "pv-input pv-mono", attrs: { id: "pv-form-totp", type: "text", autocomplete: "off", placeholder: "otpauth:// 或 base32 密钥" }, props: { value: detail.totp || "" } });
    const tagsInput = el("input", { cls: "pv-input", attrs: { id: "pv-form-tags", type: "text", autocomplete: "off", placeholder: "用逗号分隔" }, props: { value: listToCsv(detail.tags) } });
    const notesInput = el("textarea", { cls: "pv-textarea", attrs: { id: "pv-form-notes", rows: "4" }, props: { value: detail.notes || "" } });

    body.push(formFieldRow("标题", titleInput));
    body.push(formFieldRow("账号", userInput));
    body.push(formFieldRow(isNew ? "密码" : "新密码（留空表示不改）", passInput));
    body.push(formFieldRow("网址", urlInput));
    body.push(formFieldRow("动态码", totpInput));
    body.push(formFieldRow("标签", tagsInput));
    body.push(formFieldRow("备注", notesInput));

    let fieldsInput = null;
    if (isNew) {
      fieldsInput = el("textarea", {
        cls: "pv-textarea pv-mono",
        attrs: { id: "pv-form-fields", rows: "3", placeholder: "每行一个：字段名=值" },
      });
      body.push(formFieldRow("自定义字段", fieldsInput));
    } else if (Object.keys(detail.fields || {}).length) {
      const list = el("div", { cls: "pv-card" });
      Object.keys(detail.fields || {}).forEach((key) => {
        list.appendChild(el("p", { cls: "pv-hint-tight", text: key + "：值在网页里只显示掩码" }));
      });
      body.push(el("div", { cls: "pv-field" }, [
        el("p", { cls: "pv-label", text: "自定义字段" }),
        list,
        el("p", { cls: "pv-hint", text: "自定义字段的值不通过网页改写（避免把掩码写回去），需要改请用 pv edit。" }),
      ]));
    }

    openModal({
      title: isNew ? "新建记录" : "编辑记录",
      body: body,
      actions: [
        { label: "取消", autofocus: isNew ? false : true },
        {
          label: isNew ? "新建" : "保存",
          kind: "primary",
          keepOpen: true,
          onClick: async () => {
            const payload = {
              title: titleInput.value.trim(),
              username: userInput.value,
              url: urlInput.value.trim(),
              notes: notesInput.value,
              totp: totpInput.value.trim(),
              tags: csvToList(tagsInput.value),
            };
            if (!payload.title) {
              toast("标题不能空着。", "warn");
              titleInput.focus();
              return;
            }
            if (isNew) {
              if (passInput.value) payload.password = passInput.value;
              if (fieldsInput) payload.fields = parseFieldLines(fieldsInput.value);
              progressStart();
              try {
                const data = await apiRequest("POST", "/api/records", payload);
                closeModal();
                toast("已新建。");
                await loadRecords({ reset: true });
                await loadTags();
                if (data && data.id) await selectRecord(data.id);
              } catch (exc) {
                reportError(exc);
              } finally {
                progressDone();
              }
              return;
            }
            const changes = {
              title: payload.title,
              username: payload.username,
              url: payload.url,
              notes: payload.notes,
              totp: payload.totp,
              tags: payload.tags,
            };
            if (passInput.value) changes.password = passInput.value;
            progressStart();
            try {
              await apiRequest("PATCH", "/api/records/" + encodeURIComponent(detail.id), {
                changes: changes,
                expected_updated: detail.updated,
              });
              closeModal();
              toast("已保存。");
              await selectRecord(detail.id);
              await loadRecords({ reset: true });
            } catch (exc) {
              if (exc instanceof ApiError && exc.code === "record_conflict") {
                closeModal();
                state.conflict = { record_id: detail.id, kind: "update", mine: changes, theirs: null };
                await selectRecord(detail.id);
                showBanner("warn", "这条记录刚被另一个窗口改过。", [
                  { label: "保留我的", kind: "primary", onClick: () => resolveConflict(state.conflict, "mine") },
                  { label: "采用新的", onClick: () => resolveConflict(state.conflict, "theirs") },
                  { label: "并排看", onClick: () => showConflictDiff(state.conflict) },
                ]);
              } else {
                reportError(exc);
              }
            } finally {
              progressDone();
            }
          },
        },
      ],
    });
  }

  function parseFieldLines(raw) {
    const out = {};
    String(raw || "").split(/\r?\n/).forEach((line) => {
      const text = line.trim();
      if (!text) return;
      const index = text.indexOf("=");
      if (index < 0) {
        out[text] = "";
        return;
      }
      const key = text.slice(0, index).trim();
      if (!key) return;
      out[key] = text.slice(index + 1).trim();
    });
    return out;
  }

  function fieldLinesFromObject(obj) {
    const lines = [];
    Object.keys(obj || {}).forEach((key) => {
      lines.push(key + "=" + String(obj[key] === null || obj[key] === undefined ? "" : obj[key]));
    });
    return lines.join("\n");
  }

  function openDeleteDialog() {
    const detail = state.detail;
    if (!detail) return;
    const body = [
      el("p", { text: "删掉之后这条记录就没了，快照里还能找回旧版本。" }),
      el("dl", { cls: "pv-kv" }, [
        el("dt", { text: "标题" }),
        el("dd", { text: detail.title ? String(detail.title) : "(无标题)" }),
        el("dt", { text: "账号" }),
        el("dd", { text: detail.username ? String(detail.username) : "没有填写" }),
      ]),
      el("p", { cls: "pv-hint", text: "这里不展示密码。" }),
    ];
    confirmDanger({
      title: "删除这条记录？",
      body: body,
      confirmLabel: "删除",
      onConfirm: async () => {
        progressStart();
        try {
          await apiRequest("DELETE", "/api/records/" + encodeURIComponent(detail.id), {
            confirm_title: detail.title || "",
          });
          toast("已删除。");
          resetReveal();
          state.detail = null;
          state.selectedId = null;
          renderDetailEmpty();
          toggleHidden("pv-detail", true);
          await loadRecords({ reset: true });
          await loadTags();
        } catch (exc) {
          reportError(exc);
        } finally {
          progressDone();
        }
      },
    });
  }

  /* ============================================================ 10. 待整理 */
  async function refreshStagingBadge() {
    const data = await apiOptional("/api/staging");
    if (data === null) {
      state.missing.staging = true;
      updateStagingBadge(0);
      return;
    }
    state.missing.staging = false;
    state.staging.batches = toArray(data.batches);
    state.staging.count = num(data.count, state.staging.batches.length);
    const pending = state.staging.batches.filter((batch) => batch.status !== "committed" && batch.status !== "discarded").length;
    updateStagingBadge(pending);
  }

  function updateStagingBadge(count) {
    const badge = $("pv-staging-badge");
    if (!badge) return;
    const value = num(count, 0);
    badge.textContent = String(value);
    badge.hidden = value <= 0;
  }

  /** 已完结的批次：只读，且不能申请编辑锁。 */
  function isFinishedStatus(status) {
    const key = String(status || "");
    return key === "committed" || key === "rolled_back" || key === "discarded";
  }

  function batchStatusText(status) {
    const map = {
      detected: "已发现",
      drafted: "待确认 · 本地解析",
      failed: "无法识别",
      refining: "整理中 · Agent",
      review: "待确认 · Agent 整理",
      reviewing: "确认中",
      committed: "已入库",
      rolled_back: "已撤销",
      discarded: "已丢弃",
      pending: "等待确认",
      parsing: "Agent 正在整理",
      ready: "可以提交",
    };
    const key = String(status || "");
    return map[key] || key;
  }

  function batchOriginText(origin) {
    const value = String(origin || "");
    if (value === "agent_written" || value === "agent") return "Agent 整理";
    if (value === "local" || value === "local_parse" || value === "inbox") return "本地解析";
    if (!value) return "来源未知";
    return value;
  }

  async function loadStaging(options) {
    const silent = !!(options && options.silent);
    const watch = $("pv-staging-watch");
    const session = state.session || {};
    const inbox = session.inbox;
    if (inbox && inbox.watching) {
      setText("pv-staging-watch", "正在监听 " + String(inbox.dir || "inbox") + (inbox.interval ? "（每 " + inbox.interval + " 秒扫一次）" : ""));
    } else if (inbox && inbox.dir) {
      setText("pv-staging-watch", "监听没启动（" + String(inbox.dir) + "）。丢文件进去不会自动识别，可以用上面的按钮手动选文件。");
    } else {
      setText("pv-staging-watch", "监听状态未知。把文件拖进上面的区域也能导入。");
    }
    if (watch && !inbox) watch.textContent = "监听状态未知。把文件拖进上面的区域也能导入。";

    const data = await apiOptional("/api/staging");
    if (data === null) {
      state.missing.staging = true;
      toggleHidden("pv-staging-foot", true);
      toggleHidden("pv-batch-head", true);
      clearNode($("pv-batch-list"));
      toggleHidden("pv-batch-empty", false);
      setText("pv-batch-empty", "暂存区接口还没上线（此功能暂未就绪）。");
      const empty = $("pv-staging-empty");
      if (empty) {
        empty.hidden = false;
        clearNode(empty);
        empty.appendChild(el("p", { cls: "pv-empty-title", text: "待整理暂未就绪" }));
        empty.appendChild(el("p", { cls: "pv-empty-hint", text: "服务端的暂存区接口还没上线。拖拽上传也会失败，先在命令行里用 pv import。" }));
      }
      return;
    }
    state.missing.staging = false;
    state.staging.batches = toArray(data.batches);
    state.staging.count = num(data.count, state.staging.batches.length);
    renderBatches();
    const pending = state.staging.batches.filter((batch) => batch.status !== "committed" && batch.status !== "discarded").length;
    updateStagingBadge(pending);

    if (state.staging.currentId) {
      const still = state.staging.batches.some((batch) => String(batch.id) === String(state.staging.currentId));
      if (!still) {
        state.staging.currentId = null;
        state.staging.items = [];
        state.staging.batch = null;
      }
    }
    // 正在填表时（焦点还在条目卡片里）不做整块重渲染：SSE 每分钟都可能推一次，
    // 把用户敲到一半的密码清掉是最惹人烦的 bug。
    const editingNow = !!(document.activeElement && document.activeElement.closest && document.activeElement.closest("#pv-item-list"));
    const pendingSaves = Object.keys(state.staging.saveTimers).length > 0;
    if ((editingNow || pendingSaves || state.staging.touched) && state.staging.currentId) {
      return;
    }
    // silent：只刷批次列表（上传后轮询用），不自动切换当前批次 ——
    // 否则每次轮询都会 begin_edit 一次，白白抢锁还可能 409。
    if (silent) return;
    if (!state.staging.currentId && state.staging.batches.length) {
      const pending = state.staging.batches.filter((batch) => !isFinishedStatus(batch.status));
      const pick = pending.length ? pending[0] : state.staging.batches[0];
      await openBatch(String(pick.id));
    } else if (state.staging.currentId) {
      await openBatch(String(state.staging.currentId), { keepDraft: true });
    }
    if (!state.staging.batches.length) {
      showStagingBanner("", "");
      renderItems();
    }
  }

  function renderBatches() {
    const box = $("pv-batch-list");
    if (!box) return;
    clearNode(box);
    toggleHidden("pv-batch-empty", state.staging.batches.length > 0);
    state.staging.batches.forEach((batch) => {
      const id = String(batch.id);
      const selected = state.staging.currentId === id;
      const card = el("button", {
        cls: "pv-batch-card",
        attrs: { type: "button", "aria-selected": selected ? "true" : "false" },
        data: { batch: id },
      }, [
        el("span", { cls: "pv-batch-name" }, [
          el("span", { cls: "pv-dot", data: { status: String(batch.status || "") }, attrs: { "aria-hidden": "true" } }),
          el("span", { text: batch.source_file ? String(batch.source_file) : id }),
        ]),
        el("span", {
          cls: "pv-batch-meta",
          text: batchOriginText(batch.origin) + " · " + num(batch.item_count, 0) + " 条 · " + fmtRelative(batch.age_seconds) + " · " + (batch.status_label ? String(batch.status_label) : batchStatusText(batch.status)),
        }),
      ]);
      card.addEventListener("click", () => openBatch(id));
      box.appendChild(card);
    });
  }

  async function releaseBatch() {
    const staging = state.staging;
    if (!staging.currentId || !staging.editorHeld) return;
    const id = staging.currentId;
    staging.editorHeld = false;
    try {
      await apiRequest("POST", "/api/staging/" + encodeURIComponent(id) + "/edit", {
        editor_id: state.editorId,
        action: "end",
      });
    } catch (exc) {
      /* 释放失败不影响用户继续操作（服务端有超时回收） */
    }
  }

  async function openBatch(id, options) {
    const opts = options || {};
    if (!id) return;
    if (!opts.keepDraft && state.staging.currentId && state.staging.currentId !== id) {
      await flushItemSaves();
      await releaseBatch();
    }
    state.staging.currentId = String(id);
    renderBatches();
    const data = await apiOptional("/api/staging/" + encodeURIComponent(id));
    if (data === null) {
      state.staging.items = [];
      state.staging.batch = null;
      renderItems();
      toast("这批整理结果读不出来（此功能暂未就绪）。", "warn");
      return;
    }
    state.staging.batch = data.batch || state.staging.batches.filter((batch) => String(batch.id) === String(id))[0] || null;
    state.staging.originals = {};
    state.staging.items = toArray(data.items).map((item) => {
      const draft = Object.assign({ title: "", username: "", password: "", url: "", notes: "", totp: "", tags: [], fields: {} }, item.draft || {});
      const index = num(item.index, 0);
      // 原样留一份：保存时用来判断「用户真的改了」还是「把掩码原样送回来」
      state.staging.originals[index] = {
        password: String(draft.password || ""),
        totp: String(draft.totp || ""),
        fields: Object.assign({}, draft.fields || {}),
      };
      return {
        index: index,
        itemId: item.item_id ? String(item.item_id) : "",
        draft: draft,
        origin: item.origin || "",
        accepted: item.accepted !== false,
        edited: !!item.edited,
        hasError: !!item.has_error,
        warnings: toArray(item.warnings),
        conflict: item.conflict || null,
        secretFieldNames: toArray(item.secret_field_names),
      };
    });
    // 已完结（已入库/已撤销/已丢弃）的批次是只读的：**不要再申请编辑锁**。
    // 申请了服务端必定回 409「批次现在已经入库，不能开始编辑」，除了在控制台
    // 刷一排红色请求之外没有任何作用。
    if (isFinishedStatus(state.staging.batch && state.staging.batch.status)) {
      state.staging.editorHeld = false;
      const status = String((state.staging.batch && state.staging.batch.status) || "");
      showStagingBanner(
        "info",
        status === "committed"
          ? "这批已经入库了。要退回的话点右下角「撤销这批入库」。"
          : "这批已经「" + batchStatusText(status) + "」，只能看不能改。"
      );
      renderItems();
      return;
    }
    // 抢占编辑权。`taken_over === true` 才表示「我把别人的编辑权抢过来了」，
    // false 是「我干净地拿到的」—— 这里弄反会给所有正常用户弹一条假警告。
    try {
      const ticket = await apiRequest("POST", "/api/staging/" + encodeURIComponent(id) + "/edit", {
        editor_id: state.editorId,
        action: "begin",
      });
      state.staging.editorHeld = true;
      showStagingBanner("", "");
      if (ticket && ticket.taken_over === true) {
        toast("这个批次刚才被另一个标签页编辑过，现在是你在改。", "warn");
      }
    } catch (exc) {
      state.staging.editorHeld = false;
      // 409 staging_busy = 另一个窗口正拿着编辑锁。不静默吞掉：
      // 用户在下面输入会被服务端拒收，必须提前说清楚，否则就是「点了没反应」。
      const message = describeError(exc);
      showStagingBanner("warn", message + "（关掉那个标签页，或等它超时就好）", [
        { label: "再试一次", kind: "primary", onClick: () => openBatch(String(id)) },
      ]);
    }
    renderItems();
  }

  function showStagingBanner(kind, text, actions) {
    const box = $("pv-staging-banner");
    if (!box) return;
    clearNode(box);
    if (!text) return;
    const banner = el("div", { cls: "pv-banner", data: { kind: kind || "info" } }, [
      el("p", { cls: "pv-banner-text", text: text }),
    ]);
    if (toArray(actions).length) {
      const row = el("div", { cls: "pv-banner-actions" });
      actions.forEach((action) => {
        const btn = el("button", {
          cls: "pv-btn pv-btn-sm" + (action.kind === "primary" ? " pv-btn-primary" : ""),
          text: action.label,
          attrs: { type: "button" },
        });
        btn.addEventListener("click", action.onClick);
        row.appendChild(btn);
      });
      banner.appendChild(row);
    }
    box.appendChild(banner);
  }

  /** 冲突类型的中文说法（后端 ConflictKind 只有 stale / deleted 两种）。 */
  function conflictKindLabel(kind) {
    const map = {
      stale: "库里这条已被别的窗口改过",
      deleted: "库里这条已被删掉",
    };
    return map[String(kind || "")] || "库里这条的状态已经不一样了";
  }

  /** 批次级重复策略：skip / overwrite / append（服务端只有一个 mode 字段）。 */
  const MODE_CHOICES = [
    { key: "skip", label: "跳过", effect: "跳过重复的" },
    { key: "overwrite", label: "覆盖", effect: "用新内容覆盖" },
    { key: "append", label: "新建副本", effect: "建一条同名副本" },
  ];

  function modeChoice(mode) {
    const key = String(mode || "skip");
    for (let index = 0; index < MODE_CHOICES.length; index += 1) {
      if (MODE_CHOICES[index].key === key) return MODE_CHOICES[index];
    }
    return MODE_CHOICES[0];
  }

  function modeLabel(mode) {
    return modeChoice(mode).label;
  }

  function modeEffect(mode) {
    return modeChoice(mode).effect;
  }

  /**
   * 提交阶段的**记录级**冲突（HTTP 409，`{code:"record_conflict", conflicts:[…]}`）。
   *
   * 与「重复」不是一回事：重复由批次级 mode 决定（跳过/覆盖/新建副本）；
   * 这里说的是「我手里这条在库里已经被别人改过或删掉」—— 只能换策略重提，
   * 所以横幅里把冲突逐条列清楚（后端已脱敏，不含明文），并提示去改「重复时」。
   */
  function showCommitConflicts(conflicts) {
    const box = $("pv-staging-banner");
    if (!box) return;
    clearNode(box);
    const rows = toArray(conflicts);
    const list = el("ul", { cls: "pv-plain-list" });
    rows.forEach((item, index) => {
      const mine = item && item.mine && typeof item.mine === "object" ? item.mine : {};
      const theirs = item && item.theirs && typeof item.theirs === "object" ? item.theirs : null;
      const title = String(mine.title || (theirs && theirs.title) || "第 " + (index + 1) + " 条");
      list.appendChild(el("li", null, [
        el("span", { cls: "pv-item-title", text: title, attrs: { title: title } }),
        el("span", { cls: "pv-item-tail", text: conflictKindLabel(item && item.kind) }),
      ]));
    });
    const banner = el("div", { cls: "pv-banner", data: { kind: "warn" } }, [
      el("p", { cls: "pv-banner-text", text: "有 " + rows.length + " 条与库中记录冲突，这批一条都没写进去。" }),
      list,
      el("p", { cls: "pv-hint", text: "把下面的「重复时」改成 跳过 / 覆盖 / 新建副本（整批生效），再点一次提交。" }),
    ]);
    box.appendChild(banner);
  }

  function renderItems() {
    const box = $("pv-item-list");
    const empty = $("pv-staging-empty");
    if (!box) return;
    clearNode(box);
    const batch = state.staging.batch;
    const items = state.staging.items;
    const hasBatch = !!(batch && items.length);
    toggleHidden("pv-batch-head", !batch);
    toggleHidden("pv-staging-empty", hasBatch);
    toggleHidden("pv-staging-foot", !batch);
    if (empty && !hasBatch) {
      empty.hidden = false;
    }
    if (!batch) {
      setText("pv-batch-head-title", "");
      setText("pv-batch-head-meta", "");
      updateFoot();
      return;
    }
    setText("pv-batch-head-title", batch.source_file ? String(batch.source_file) : String(batch.id || ""));
    const status = String(batch.status || "");
    let metaText = batchOriginText(batch.origin) + " · " + items.length + " 条 · " + batchStatusText(status);
    if (status === "parsing") {
      const age = num(batch.age_seconds, 0);
      metaText = "Agent 正在整理·已用时 " + age + " 秒（超过 3 分钟会自动回到本地结果）";
    }
    setText("pv-batch-head-meta", metaText);
    toggleHidden("pv-rollback", status !== "committed");

    const finished = isFinishedStatus(batch.status);
    items.forEach((item) => {
      box.appendChild(renderItemCard(item, finished));
    });
    updateFoot();
  }

  function renderItemCard(item, readOnly) {
    const index = item.index;
    const card = el("div", {
      cls: "pv-item-card",
      data: { index: index, accepted: item.accepted ? "true" : "false" },
    });

    const checkbox = el("input", { attrs: { type: "checkbox", id: "pv-item-accept-" + index } });
    checkbox.checked = !!item.accepted;
    checkbox.disabled = !!readOnly;
    checkbox.addEventListener("change", () => {
      item.accepted = checkbox.checked;
      card.dataset.accepted = checkbox.checked ? "true" : "false";
      updateFoot();
      scheduleItemSave(index);
    });

    const head = el("div", { cls: "pv-item-head" }, [
      el("span", { cls: "pv-item-index", text: "#" + (index + 1) }),
      el("label", { cls: "pv-item-check", attrs: { for: "pv-item-accept-" + index } }, [checkbox, document.createTextNode("接受这条")]),
      el("div", { cls: "pv-item-meta" }, [
        item.origin ? el("span", { cls: "pv-chip", text: batchOriginText(item.origin) }) : null,
        item.edited ? el("span", { cls: "pv-chip", text: "已编辑" }) : null,
      ]),
    ]);
    card.appendChild(head);

    if (toArray(item.warnings).length || item.conflict) {
      const warnBox = el("div", { cls: "pv-item-warn" });
      toArray(item.warnings).forEach((warning) => {
        const level = String((warning && warning.level) || "info");
        warnBox.appendChild(el("p", {
          cls: "pv-warn",
          data: { level: level === "error" ? "error" : level },
          text: (warning && warning.message) ? String(warning.message) : "这条有个提醒。",
        }));
      });
      if (item.conflict) {
        const conflictBar = el("div", { cls: "pv-warn", data: { level: "conflict" } }, [
          el("p", { text: item.conflict.message ? String(item.conflict.message) : "库里已经有一条同名记录了。" }),
        ]);
        const row = el("div", { cls: "pv-banner-actions" });
        // 服务端的重复策略是**批次级**（commit 的 mode: skip / overwrite / append），
        // 所以这里点选改变的是整批的策略，卡片上写清楚，别让用户以为只影响这一条。
        const choices = MODE_CHOICES;
        choices.forEach((choice) => {
          const active = state.staging.mode === choice.key;
          const btn = el("button", {
            cls: "pv-btn pv-btn-sm" + (active ? " pv-btn-primary" : ""),
            text: choice.label,
            attrs: { type: "button", "aria-pressed": active ? "true" : "false" },
          });
          btn.addEventListener("click", () => {
            state.staging.mode = choice.key;
            if (choice.key === "skip") item.accepted = false;
            else item.accepted = true;
            renderItems();
            scheduleItemSave(index);
            toast("整批重复记录都会按「" + choice.label + "」处理。");
          });
          row.appendChild(btn);
        });
        conflictBar.appendChild(row);
        conflictBar.appendChild(el("p", {
          cls: "pv-hint-tight",
          text: "这个选择对整个批次生效：" + modeEffect(state.staging.mode),
        }));
        warnBox.appendChild(conflictBar);
      }
      card.appendChild(warnBox);
    }

    const form = el("div", { cls: "pv-item-form" });
    const plainFields = [
      { key: "title", label: "标题", value: item.draft.title || "" },
      { key: "username", label: "账号", value: item.draft.username || "" },
    ];
    plainFields.forEach((spec) => {
      const id = "pv-item-" + index + "-" + spec.key;
      const input = el("input", {
        cls: "pv-input",
        attrs: { id: id, type: "text", autocomplete: "off" },
        data: { f: spec.key },
        props: { value: spec.value },
      });
      input.addEventListener("input", () => {
        scheduleItemSave(index);
      });
      form.appendChild(el("div", { cls: "pv-field" }, [
        el("label", { cls: "pv-label", text: spec.label, attrs: { for: id } }),
        input,
      ]));
    });

    // 密码 / 动态码：服务端**默认掩码**（DESIGN §9.4），所以这里留空 + 提示，
    // 用户真填了才发送。把掩码原样送回去会把草稿里的密码改成「••••」——那是最坏的一种数据损坏。
    const secretSpecs = [
      { key: "password", label: "密码", original: (state.staging.originals[index] || {}).password || "" },
      { key: "totp", label: "动态码", original: (state.staging.originals[index] || {}).totp || "" },
    ];
    secretSpecs.forEach((spec) => {
      const id = "pv-item-" + index + "-" + spec.key;
      const hasValue = !!spec.original && spec.original !== EMPTY_MASK;
      const input = el("input", {
        cls: "pv-input pv-mono",
        attrs: {
          id: id,
          type: "password",
          autocomplete: "off",
          placeholder: hasValue ? "已保存 · 改就输入" : "没填",
        },
        data: { f: spec.key },
        props: { value: "" },
      });
      input.addEventListener("input", () => {
        scheduleItemSave(index);
      });
      const rowChildren = [input];
      if (hasValue) {
        // 掩码字段的显隐按钮放在输入框右侧（同一行），不然这一格会比邻居高一截
        const control = setupRevealControl(index, spec.key, input, spec.label);
        rowChildren.push(control.countdown);
        rowChildren.push(control.button);
      }
      form.appendChild(el("div", { cls: "pv-field" }, [
        el("label", { cls: "pv-label", text: spec.label, attrs: { for: id } }),
        el("div", { cls: "pv-input-row" }, rowChildren),
      ]));
    });

    const urlId = "pv-item-" + index + "-url";
    const urlInput = el("input", {
      cls: "pv-input", attrs: { id: urlId, type: "text", autocomplete: "off", placeholder: "https://" },
      data: { f: "url" }, props: { value: item.draft.url || "" },
    });
    urlInput.addEventListener("input", () => scheduleItemSave(index));
    form.appendChild(el("div", { cls: "pv-field" }, [
      el("label", { cls: "pv-label", text: "网址", attrs: { for: urlId } }),
      urlInput,
    ]));

    const tagsId = "pv-item-" + index + "-tags";
    const tagsInput = el("input", {
      cls: "pv-input", attrs: { id: tagsId, type: "text", autocomplete: "off", placeholder: "用逗号分隔" },
      data: { f: "tags" }, props: { value: listToCsv(item.draft.tags) },
    });
    tagsInput.addEventListener("input", () => scheduleItemSave(index));
    form.appendChild(el("div", { cls: "pv-field" }, [
      el("label", { cls: "pv-label", text: "标签", attrs: { for: tagsId } }),
      tagsInput,
    ]));

    const notesId = "pv-item-" + index + "-notes";
    const notes = el("textarea", {
      cls: "pv-textarea", attrs: { id: notesId, rows: "2" }, data: { f: "notes" },
      props: { value: item.draft.notes || "" },
    });
    notes.addEventListener("input", () => scheduleItemSave(index));
    form.appendChild(el("div", { cls: "pv-field pv-wide" }, [
      el("label", { cls: "pv-label", text: "备注", attrs: { for: notesId } }),
      notes,
    ]));

    const fieldsId = "pv-item-" + index + "-fields";
    const custom = el("textarea", {
      cls: "pv-textarea pv-mono",
      attrs: { id: fieldsId, rows: "2", placeholder: "每行一个：字段名=值" },
      data: { f: "fields" },
      props: { value: fieldLinesFromObject(item.draft.fields) },
    });
    custom.addEventListener("input", () => scheduleItemSave(index));
    form.appendChild(el("div", { cls: "pv-field pv-wide" }, [
      el("label", { cls: "pv-label", text: "自定义字段", attrs: { for: fieldsId } }),
      custom,
      el("p", { cls: "pv-hint pv-hint-tight", text: "带 •••• 的是已保存的敏感字段，原样留着就不会被改动。" }),
    ]));

    Array.prototype.forEach.call(form.querySelectorAll("input, textarea"), (node) => {
      node.disabled = !!readOnly;
    });
    card.appendChild(form);

    if (!readOnly) {
      const foot = el("div", { cls: "pv-item-meta" }, [
        el("button", {
          cls: "pv-btn pv-btn-sm pv-btn-ghost", text: "保存这条", attrs: { type: "button" },
          on: { click: () => saveItem(index) },
        }),
      ]);
      card.appendChild(foot);
    }

    return card;
  }

  /**
   * 暂存区单个敏感字段的显隐控制。
   *
   * 服务端 `GET /api/staging/{id}?reveal=<field>&index=N` 才给明文；15 秒后这里主动
   * 把明文从 DOM 撤掉（连 input.value 一起清空），避免掩码被误当值写回草稿。
   */
  function setupRevealControl(index, field, input, label) {
    const button = el("button", {
      cls: "pv-link-btn", text: "显示", attrs: { type: "button", "aria-label": "显示这条草稿的" + label },
    });
    const countdown = el("span", { cls: "pv-countdown", text: "" });
    let timer = 0;

    function hide() {
      if (timer) {
        window.clearInterval(timer);
        timer = 0;
      }
      input.type = "password";
      input.value = "";
      input.dataset.revealed = "0";
      button.textContent = "显示";
      countdown.textContent = "";
    }

    button.addEventListener("click", async () => {
      if (input.dataset.revealed === "1") {
        hide();
        return;
      }
      const staging = state.staging;
      if (!staging.currentId) return;
      try {
        const data = await apiRequest(
          "GET",
          "/api/staging/" + encodeURIComponent(staging.currentId) + "?reveal=" + encodeURIComponent(field) + "&index=" + index
        );
        const value = data && data.value !== undefined && data.value !== null ? String(data.value) : "";
        if (!value) {
          toast("这条草稿的这个字段是空的。", "warn");
          return;
        }
        input.type = "text";
        input.value = value;
        input.dataset.revealed = "1";
        button.textContent = "隐藏";
        const deadline = Date.now() + REVEAL_SECONDS * 1000;
        countdown.textContent = REVEAL_SECONDS + "s";
        if (timer) window.clearInterval(timer);
        timer = window.setInterval(() => {
          const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
          if (left <= 0) {
            hide();
            return;
          }
          countdown.textContent = left + "s";
        }, 1000);
      } catch (exc) {
        reportError(exc);
      }
    });

    return { button: button, countdown: countdown };
  }

  function scheduleItemSave(index) {
    const timers = state.staging.saveTimers;
    state.staging.touched = true;
    if (timers[index]) window.clearTimeout(timers[index]);
    timers[index] = window.setTimeout(() => {
      delete timers[index];
      saveItem(index, { quiet: true });
    }, 700);
  }

  /**
   * 从卡片表单里读一份草稿。
   *
   * 关键点：**只送用户真的改过的东西**。
   *   - 密码/动态码：默认空着（服务端给的是掩码），空着就不送 → 服务端保留原值；
   *   - 自定义字段：值与服务端给的掩码一模一样时跳过（`_merged_record` 是合并语义，
   *     只送改动的键不会把别的字段清掉）。
   */
  function collectDraft(index) {
    const card = document.querySelector('.pv-item-card[data-index="' + index + '"]');
    if (!card) return null;
    const read = (key) => {
      const node = card.querySelector('[data-f="' + key + '"]');
      return node ? node.value : "";
    };
    const original = state.staging.originals[index] || { password: "", totp: "", fields: {} };
    const draft = {
      title: read("title").trim(),
      username: read("username"),
      url: read("url").trim(),
      notes: read("notes"),
      tags: csvToList(read("tags")),
    };
    const password = read("password");
    if (password && password !== EMPTY_MASK && !MASK_ONLY.test(password)) draft.password = password;
    const totp = read("totp");
    if (totp && totp !== EMPTY_MASK && !MASK_ONLY.test(totp)) draft.totp = totp;
    const parsedFields = parseFieldLines(read("fields"));
    const changedFields = {};
    Object.keys(parsedFields).forEach((key) => {
      const value = parsedFields[key];
      const before = (original.fields || {})[key];
      if (value === EMPTY_MASK) return;
      if (before !== undefined && String(before) === value && MASK_ONLY.test(value)) return;
      changedFields[key] = value;
    });
    if (Object.keys(changedFields).length) draft.fields = changedFields;
    return draft;
  }

  async function flushItemSaves() {
    const timers = state.staging.saveTimers;
    const pending = Object.keys(timers);
    pending.forEach((key) => {
      window.clearTimeout(timers[key]);
      delete timers[key];
    });
    if (!pending.length) return true;
    for (const key of pending) {
      const ok = await saveItem(Number(key), { quiet: true });
      if (!ok) return false;
    }
    return true;
  }

  async function saveItem(index, options) {
    const opts = options || {};
    const staging = state.staging;
    if (!staging.currentId) return false;
    const item = staging.items.filter((entry) => entry.index === index)[0];
    if (!item) return false;
    const draft = collectDraft(index);
    if (!draft) return false;
    // 本地缓存只更新用户改过的键；密码/动态码保持服务端给的掩码（不往外送）
    item.draft = Object.assign({}, item.draft, draft, {
      password: item.draft.password,
      totp: item.draft.totp,
      fields: Object.assign({}, item.draft.fields, draft.fields || {}),
    });
    const payload = {
      items: [{
        index: index,
        draft: draft,
        accepted: !!item.accepted,
      }],
      editor_id: state.editorId,
    };
    try {
      const data = await apiRequest("PATCH", "/api/staging/" + encodeURIComponent(staging.currentId) + "/items", payload, {
        "X-PV-Editor-Id": state.editorId,
      });
      if (data && data.item_count !== undefined) {
        const batch = staging.batch;
        if (batch) batch.item_count = num(data.item_count, batch.item_count);
      }
      if (!opts.quiet) toast("这一条已保存。");
      if (Object.keys(staging.saveTimers).length === 0) staging.touched = false;
      updateFoot();
      return true;
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 404) {
        toast("暂存区编辑接口还没上线（此功能暂未就绪）。", "warn");
      } else {
        reportError(exc);
      }
      return false;
    }
  }

  function updateFoot() {
    const items = state.staging.items;
    // has_error 的条目服务端不会入库（accepted_count 也不算它），这里保持一致
    const accepted = items.filter((item) => item.accepted && !item.hasError).length;
    const commit = $("pv-commit");
    const count = $("pv-accept-count");
    if (count) count.textContent = "已接受 " + accepted + " / " + items.length + " 条";
    if (commit) {
      commit.textContent = "提交 " + accepted + " 条";
      const status = String((state.staging.batch && state.staging.batch.status) || "");
      const finished = status === "committed" || status === "rolled_back" || status === "discarded";
      commit.disabled = accepted === 0 || finished || !state.staging.items.length;
      commit.title = accepted === 0 ? "先勾选要入库的条目" : "";
    }
    const acceptAll = $("pv-accept-all");
    if (acceptAll) {
      const allAccepted = items.length > 0 && items.every((item) => item.accepted);
      acceptAll.textContent = allAccepted ? "全不选" : "全选";
    }
    const discard = $("pv-discard");
    const batchStatus = String((state.staging.batch && state.staging.batch.status) || "");
    if (discard) {
      discard.disabled = batchStatus === "discarded" || !state.staging.items.length;
      discard.hidden = isFinishedStatus(batchStatus);
    }
    const acceptAllBtn = $("pv-accept-all");
    if (acceptAllBtn) acceptAllBtn.hidden = isFinishedStatus(batchStatus);
    const modeBox = $("pv-mode");
    if (modeBox) modeBox.hidden = isFinishedStatus(batchStatus);
    Array.prototype.forEach.call(document.querySelectorAll("#pv-mode [data-mode]"), (button) => {
      button.setAttribute("aria-pressed", button.dataset.mode === state.staging.mode ? "true" : "false");
    });
  }

  async function toggleAcceptAll() {
    const items = state.staging.items;
    if (!items.length) return;
    const allAccepted = items.every((item) => item.accepted);
    items.forEach((item) => {
      item.accepted = !allAccepted;
    });
    renderItems();
    const results = await Promise.all(items.map((item) => saveItem(item.index, { quiet: true })));
    if (results.every((ok) => ok)) toast(allAccepted ? "全部忽略了。" : "全部接受了。");
  }

  async function commitBatch() {
    const staging = state.staging;
    if (!staging.currentId) return;
    const flushed = await flushItemSaves();
    if (!flushed) {
      toast("有几条没保存成功，先修一下再提交。", "warn");
      return;
    }
    const acceptedItems = staging.items.filter((item) => item.accepted && !item.hasError);
    if (!acceptedItems.length) return;
    progressStart();
    const button = $("pv-commit");
    if (button) button.disabled = true;
    const body = {
      editor_id: state.editorId,
      mode: staging.mode,
    };
    const ids = acceptedItems.map((item) => item.itemId).filter((id) => !!id);
    if (ids.length) body.accept_item_ids = ids;
    try {
      const data = await apiRequest("POST", "/api/staging/" + encodeURIComponent(staging.currentId) + "/commit", body);
      const committed = data && data.committed !== undefined ? num(data.committed, 0) : toArray(data && data.ids).length;
      const skipped = num(data && data.skipped, 0);
      if (data && data.already_committed === true) {
        // 重复提交是**幂等成功**（HTTP 200 + committed:0），不是错误，别再弹红框
        toast("这批之前已经入库过了，不会重复写入。", "info", data.hint ? String(data.hint) : "");
      } else if (committed === 0) {
        toast("这批没有需要写入的条目。", "info", skipped > 0 ? "跳过了 " + skipped + " 条重复记录。" : "");
      } else {
        toast(
          "已入库 " + committed + " 条。",
          "info",
          skipped > 0 ? "另有 " + skipped + " 条重复，按「" + modeLabel(staging.mode) + "」处理了。" : ""
        );
      }
      staging.items = [];
      staging.batch = null;
      staging.currentId = null;
      staging.touched = false;
      showStagingBanner("info", "");
      await loadStaging();
      await loadRecords({ reset: true });
      await loadTags();
    } catch (exc) {
      if (exc instanceof ApiError && exc.code === "record_conflict") {
        const conflicts = toArray(exc.data && exc.data.conflicts);
        showCommitConflicts(conflicts);
        toast(
          "有 " + Math.max(conflicts.length, 1) + " 条与库中记录冲突，这批没有写入。",
          "warn",
          "换一种「重复时」策略再提交一次。"
        );
        await loadStaging();
      } else {
        reportError(exc);
      }
    } finally {
      if (button) button.disabled = false;
      progressDone();
    }
  }

  function discardBatch() {
    const staging = state.staging;
    if (!staging.currentId) return;
    const batch = staging.batch || {};
    confirmDanger({
      title: "丢弃这批整理结果？",
      body: [
        el("p", { text: "整批草稿会被丢掉，库里的记录不受影响。" }),
        el("p", { cls: "pv-hint", text: batch.source_file ? "文件：" + String(batch.source_file) : "" }),
      ],
      confirmLabel: "丢弃",
      onConfirm: async () => {
        progressStart();
        try {
          await apiRequest("POST", "/api/staging/" + encodeURIComponent(staging.currentId) + "/discard", {});
          toast("已丢弃这批。");
          staging.items = [];
          staging.batch = null;
          staging.currentId = null;
          await loadStaging();
        } catch (exc) {
          reportError(exc);
        } finally {
          progressDone();
        }
      },
    });
  }

  async function rollbackBatch() {
    const staging = state.staging;
    if (!staging.currentId) return;
    progressStart();
    try {
      const data = await apiRequest("POST", "/api/staging/" + encodeURIComponent(staging.currentId) + "/rollback", {});
      toast("已撤销 " + num(data && data.rolled_back, 0) + " 条入库记录。");
      await loadStaging();
      await loadRecords({ reset: true });
    } catch (exc) {
      if (exc instanceof ApiError && exc.status === 404) {
        toast("撤销接口还没上线（此功能暂未就绪）。", "warn");
      } else {
        reportError(exc);
      }
    } finally {
      progressDone();
    }
  }

  async function uploadFiles(fileList) {
    const files = Array.prototype.slice.call(fileList || []);
    if (!files.length) return;
    if (!state.session || !state.session.unlocked) {
      toast("先解锁再把文件拖进来。", "warn");
      return;
    }
    if (state.page !== "staging") await showPage("staging");
    // 契约：上传是异步的 —— 响应只说「收下了」，草稿批次由服务端后台识别后出现。
    // 所以这里绝不能立刻断言「已经有批次了」，只能等 SSE / 轮询。
    const beforeCount = num(state.staging.count, 0);
    toast("已收下，正在识别…", "info", "识别完会自己出现在下面，不用刷新。");
    let done = 0;
    for (const file of files) {
      try {
        const buffer = await file.arrayBuffer();
        const response = await fetch("/api/inbox/upload", {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/octet-stream",
            "X-Filename": encodeURIComponent(file.name || "import.txt"),
          },
          body: buffer,
        });
        if (!response.ok) {
          let detail = "";
          try {
            const payload = await response.json();
            detail = payload && payload.message ? String(payload.message) : "";
          } catch (exc) {
            detail = "";
          }
          if (response.status === 404) {
            toast("拖拽上传的接口还没上线（此功能暂未就绪）。", "warn", "可以先用 pv import 导入同一份文件。");
          } else {
            toast("「" + (file.name || "文件") + "」没收下：" + (detail || defaultHttpMessage(response.status)), "danger");
          }
          continue;
        }
        done += 1;
      } catch (exc) {
        toast("「" + (file.name || "文件") + "」上传失败，网络或服务可能断了。", "danger");
      }
    }
    if (done > 0) {
      toast("收到 " + done + " 个文件。", "info", "识别要花几秒，好了会自己刷新出来。");
      await waitForNewBatch(beforeCount);
    }
  }

  /**
   * 上传后等新批次出现：先靠 SSE（`staging` 事件），这里补最多 4 次轮询兜底。
   * 识别完成时间不可预期，所以超时**不算失败**，只提示「还在识别」。
   */
  async function waitForNewBatch(beforeCount) {
    const delays = [900, 1600, 2600, 4000];
    for (let index = 0; index < delays.length; index += 1) {
      await new Promise((resolve) => window.setTimeout(resolve, delays[index]));
      if (state.page !== "staging") return;
      await loadStaging({ silent: true });
      if (num(state.staging.count, 0) > beforeCount) {
        toast("识别完成，可以开始整理了。");
        return;
      }
    }
    if (state.page === "staging") {
      toast("还在识别，稍等一下。", "info", "列表会自己刷新；也可以点上面的刷新。");
    }
  }

  async function openInboxFolder() {
    const inbox = (state.session && state.session.inbox) || null;
    const dir = inbox && inbox.dir ? String(inbox.dir) : "";
    if (!dir) {
      toast("还不知道 inbox 目录在哪（服务端没报上来）。", "warn");
      return;
    }
    // 浏览器不能调起资源管理器；这里把路径放进剪贴板，让用户粘到地址栏。
    const copied = await copyText(dir);
    if (copied) toast("路径已复制：粘到资源管理器地址栏就能打开。", "info", dir);
    else toast("浏览器不让写剪贴板。手动打开这个目录：", "warn", dir);
  }

  async function copyText(text) {
    const value = String(text || "");
    if (!value) return false;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(value);
        return true;
      }
    } catch (exc) {
      /* 继续走兜底 */
    }
    try {
      const area = el("textarea", { cls: "pv-sr-only", props: { value: value } });
      document.body.appendChild(area);
      area.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(area);
      return !!ok;
    } catch (exc) {
      return false;
    }
  }

  /* ============================================================ 11. 健康检查 */
  function normalizeHealth(raw) {
    const data = raw || {};
    const weak = toArray(data.weak || data.weak_passwords).map((item) => ({
      id: item && item.id ? String(item.id) : "",
      title: item && item.title ? String(item.title) : "(无标题)",
      entropy: num(item && item.entropy, 0),
      level: item && item.level ? String(item.level) : "",
    }));
    const reused = toArray(data.reused_groups || data.reused_passwords).map((group) => {
      if (Array.isArray(group)) return { titles: group.map(String), count: group.length };
      const titles = toArray(group && (group.titles || group.records)).map(String);
      return { titles: titles, count: num(group && group.count, titles.length) };
    });
    const stale = toArray(data.stale || data.stale_passwords).map((item) => ({
      id: item && item.id ? String(item.id) : "",
      title: item && item.title ? String(item.title) : "(无标题)",
      days: num(item && item.days, 0),
    }));
    const noPassword = toArray(data.no_password || data.without_password).map((item) => ({
      id: item && item.id ? String(item.id) : "",
      title: item && item.title ? String(item.title) : String(item),
    }));
    return { weak: weak, reused: reused, stale: stale, noPassword: noPassword, snapshot: data.snapshot || null, total: num(data.total, 0) };
  }

  async function loadHealth() {
    const data = await apiOptional("/api/health");
    if (data === null) {
      state.missing.health = true;
      state.health = null;
      renderHealth();
      return;
    }
    state.missing.health = false;
    state.healthError = "";
    state.health = normalizeHealth(data);
    renderHealth();
  }

  function statCard(label, value, tone) {
    return el("div", { cls: "pv-stat-card" }, [
      el("span", { cls: "pv-stat-value", text: String(value), data: { tone: tone || "" } }),
      el("span", { cls: "pv-stat-label", text: label }),
    ]);
  }

  function renderHealth() {
    const box = $("pv-health-stats");
    if (!box) return;
    clearNode(box);
    const health = state.health;
    if (state.missing.health) {
      box.appendChild(el("div", { cls: "pv-card", text: "体检接口还没上线（此功能暂未就绪）。命令行里 pv doctor 有同样的内容。" }));
      toggleHidden("pv-health-weak-empty", true);
      toggleHidden("pv-health-reused-empty", true);
      toggleHidden("pv-health-stale-empty", true);
      setText("pv-health-backup", "体检接口还没上线，暂时看不到快照天数。");
      clearNode($("pv-health-weak"));
      clearNode($("pv-health-reused"));
      clearNode($("pv-health-stale"));
      return;
    }
    if (!health) {
      box.appendChild(el("div", { cls: "pv-card", text: "还没有体检数据。" }));
      return;
    }
    box.appendChild(statCard("弱密码", health.weak.length, health.weak.length ? "warn" : "accent"));
    box.appendChild(statCard("密码复用组", health.reused.length, health.reused.length ? "warn" : "accent"));
    box.appendChild(statCard("超过 365 天", health.stale.length, health.stale.length ? "danger" : "accent"));
    box.appendChild(statCard("无密码条目", health.noPassword.length, health.noPassword.length ? "warn" : "accent"));

    const weakBox = $("pv-health-weak");
    clearNode(weakBox);
    health.weak.forEach((item) => {
      const li = el("li", null, [
        el("span", { cls: "pv-item-title", text: item.title, attrs: { title: item.title } }),
        el("span", { cls: "pv-item-tail", text: "熵 " + item.entropy + " bit · " + (item.level || "偏弱") }),
      ]);
      li.addEventListener("click", () => {
        if (!item.id) return;
        showPage("records");
        selectRecord(item.id);
      });
      weakBox.appendChild(li);
    });
    toggleHidden("pv-health-weak-empty", health.weak.length > 0);

    const reusedBox = $("pv-health-reused");
    clearNode(reusedBox);
    health.reused.forEach((group) => {
      const li = el("li", null, [
        el("span", { cls: "pv-item-title", text: group.titles.join(" · ") || "(没有标题)" }),
        el("span", { cls: "pv-item-tail", text: group.count + " 条共用同一个密码" }),
      ]);
      reusedBox.appendChild(li);
    });
    toggleHidden("pv-health-reused-empty", health.reused.length > 0);

    const staleBox = $("pv-health-stale");
    clearNode(staleBox);
    health.stale.forEach((item) => {
      const li = el("li", null, [
        el("span", { cls: "pv-item-title", text: item.title, attrs: { title: item.title } }),
        el("span", { cls: "pv-item-tail", text: item.days + " 天没换" }),
      ]);
      staleBox.appendChild(li);
    });
    toggleHidden("pv-health-stale-empty", health.stale.length > 0);

    const backup = $("pv-health-backup");
    clearNode(backup);
    const snapshot = health.snapshot;
    if (!snapshot) {
      backup.appendChild(el("p", { text: "服务端没报快照信息。用 pv doctor 看一眼最近一次备份。" }));
    } else {
      const days = snapshot.last_days;
      const daysText = days === null || days === undefined ? "还不知道上次快照是哪天" : (days <= 0 ? "今天刚快照过" : "距上次快照 " + days + " 天");
      backup.appendChild(el("p", { text: daysText }));
      if (snapshot.dir) backup.appendChild(el("p", { cls: "pv-hint-tight", text: "快照目录：" + String(snapshot.dir) }));
      if (snapshot.looks_synced) {
        backup.appendChild(el("p", { cls: "pv-hint-tight", text: "这个目录看着像网盘同步目录（OneDrive / 坚果云 / Dropbox / Google Drive）。这样即使本机硬盘坏了，旧快照也能捞回来 —— 挺好。" }));
      } else {
        backup.appendChild(el("p", { cls: "pv-hint-tight", text: "这个目录不在常见网盘同步目录里。建议把 data.enc 放到 OneDrive 或坚果云，多一层保险。" }));
      }
    }
  }

  /* ============================================================== 12. 设置 */
  function kvRow(key, value) {
    return [el("dt", { text: key }), el("dd", { text: value })];
  }

  /* ---- MCP 一键接入 --------------------------------------------------------
   * 配置整段来自 `GET /api/mcp-config`，`command` / `args` / `env` 一字不改地
   * JSON.stringify 进 <pre>。**绝不自己拼参数**：后端曾经把 args 拼成 ["mcp"]，
   * python 把 mcp 当成文件名，客户端不报错、只是静默显示「零个工具」——
   * 这种失败模式用户查不出来，所以宁可不给按钮也不能猜。
   */

  /** 两个客户端都要显示：只显示一个，用户会以为另一个接不上。 */
  const MCP_CLIENTS = [
    { key: "workbuddy", label: "WorkBuddy", where: "~/.workbuddy/mcp.json" },
    { key: "deepseek_harness", label: "deepseek-harness", where: "MCP 配置段（stdio）" },
  ];

  /** 「改完必须重启客户端」是唯一零报错的失败模式，按内容识别后加重显示。 */
  function isCriticalNote(text) {
    return /重启/.test(String(text || ""));
  }

  /** 一张客户端卡片：hint 在 <pre> 上方，复制按钮复制整段（含外层包裹键）。 */
  function buildMcpCard(client, payload) {
    const text = JSON.stringify(payload.config, null, 2);
    const copyBtn = el("button", {
      cls: "pv-btn pv-btn-sm",
      text: "复制",
      attrs: {
        type: "button",
        "aria-label": "复制 " + client.label + " 的 MCP 配置",
        title: "复制整段配置（含最外层包裹键）",
      },
    });
    copyBtn.addEventListener("click", async () => {
      const ok = await copyText(text);
      if (ok) toast(client.label + " 的配置已复制，粘进客户端就能用。");
      else toast("浏览器不让写剪贴板，手动全选这段 JSON 复制吧。", "warn");
    });

    const head = el("div", { cls: "pv-mcp-head" }, [
      el("h3", { cls: "pv-mcp-title", text: client.label }),
      el("span", { cls: "pv-chip pv-mono", text: client.where }),
      copyBtn,
    ]);
    const hint = el("p", { cls: "pv-hint", text: String(payload.hint || "") });
    const pre = el("pre", { cls: "pv-code pv-mono", text: text });
    return el("section", { cls: "pv-mcp-card" }, [head, hint, pre]);
  }

  /** 注意事项：逐条渲染、不折叠；「必须重启」那条加警示色左竖线。 */
  function buildMcpNotes(notes) {
    const list = el("div", { cls: "pv-note-list" });
    let count = 0;
    toArray(notes).forEach((raw) => {
      const text = String(raw || "").trim();
      if (!text) return;
      count += 1;
      list.appendChild(el("p", {
        cls: "pv-note",
        text: text,
        data: isCriticalNote(text) ? { strong: "true" } : null,
      }));
    });
    if (!count) list.appendChild(el("p", { cls: "pv-note", text: "服务端没给注意事项。" }));
    return el("section", { cls: "pv-section" }, [
      el("h4", { cls: "pv-section-title", text: "注意事项（请先看完再粘）" }),
      list,
    ]);
  }

  /** 工具清单：只显示名字与条数，够用户核对「是不是 10 个」。 */
  function buildMcpTools(tools) {
    const names = toArray(tools).map((name) => String(name || "")).filter(Boolean);
    const hint = names.length
      ? "在客户端的工具列表里看到下面 " + names.length + " 个 vault_* 工具，就是接上了。"
      : "服务端没读到工具清单，接入后以客户端里实际列出的工具为准。";
    const wrap = el("section", { cls: "pv-section" }, [
      el("h4", { cls: "pv-section-title", text: "怎么算接入成功" }),
      el("p", { cls: "pv-hint", text: hint }),
    ]);
    if (names.length) {
      wrap.appendChild(el("p", { cls: "pv-tool-list", text: names.join("  ") }));
    }
    return wrap;
  }

  /** 只读展示服务端给的三条路径 —— 只给人看，绝不拼回配置里。 */
  function buildMcpPaths(data) {
    const dl = el("dl", { cls: "pv-kv" });
    [
      ["python", data.python, "（服务端没报解释器路径，请自己填 python.exe 的绝对路径）"],
      ["pv.py 入口", data.entry, "（服务端没定位到 pv.py）"],
      ["库文件", data.vault, "（服务端没报库路径）"],
    ].forEach((row) => {
      dl.appendChild(el("dt", { text: row[0] }));
      dl.appendChild(el("dd", {
        cls: "pv-mono",
        text: row[1] ? String(row[1]) : row[2],
      }));
    });
    return dl;
  }

  /** 404 / 401 降级：不白屏、不吞错，给一条手动命令。 */
  function renderMcpFallback(block, reason) {
    clearNode(block);
    block.appendChild(el("p", {
      cls: "pv-hint",
      text: "此项功能暂未就绪" + (reason ? "（" + reason + "）" : "") + "。",
    }));
    block.appendChild(el("p", {
      cls: "pv-hint",
      text: "手动取配置：在项目目录里跑 python pv.py mcp；这个子命令还没上线的话，"
        + "用 python -m pwdvault.mcp_server 的启动参数自己写 command / args / env 三项。",
    }));
    block.appendChild(el("p", {
      cls: "pv-hint",
      text: "args 不要写成 [\"mcp\"]：python 会把它当成文件名，客户端只会显示零个工具。",
    }));
  }

  /** 设置页里的 MCP 一块。data 缓存进 state，避免每次 revision 重渲染都重发请求。 */
  async function renderMcpBlock() {
    const block = $("pv-mcp-block");
    if (!block) return;
    let data = state.mcpConfig;
    if (data === undefined) {
      try {
        data = await apiOptional("/api/mcp-config");
      } catch (exc) {
        // 401（会话失效）与 404（路由没上线）都按「暂未就绪」处理，不弹错误框
        data = null;
      }
      state.mcpConfig = data;
    }
    clearNode(block);
    if (!data || typeof data !== "object") {
      renderMcpFallback(block, "");
      return;
    }
    block.appendChild(buildMcpPaths(data));
    block.appendChild(buildMcpNotes(data.notes));
    MCP_CLIENTS.forEach((client) => {
      const payload = data[client.key];
      if (!payload || typeof payload !== "object" || !payload.config) {
        block.appendChild(el("section", { cls: "pv-mcp-card" }, [
          el("div", { cls: "pv-mcp-head" }, [
            el("h3", { cls: "pv-mcp-title", text: client.label }),
          ]),
          el("p", { cls: "pv-hint", text: "这个客户端的配置暂未就绪（服务端没返回）。" }),
        ]));
        return;
      }
      block.appendChild(buildMcpCard(client, payload));
    });
    block.appendChild(buildMcpTools(data.tools));
  }

  async function renderSettings() {
    const session = state.session || {};
    const security = $("pv-settings-security");
    clearNode(security);
    const methods = toArray(session.methods);
    const autoLock = num(session.auto_lock_seconds, -1);
    [
      kvRow("自动锁定", fmtMinutes(autoLock)),
      kvRow("本机免密", methods.indexOf("dpapi") >= 0 ? "已启用（这台电脑上不用输主密码）" : "未启用"),
      kvRow("解锁方式", methods.length ? methods.join(" / ") : "未知"),
      kvRow("剪贴板清空", state.lastCopy && state.lastCopy.auto_clear === true
        ? "上次复制：" + num(state.lastCopy.auto_clear_in, 0) + " 秒后清空（" + String(state.lastCopy.auto_clear_mode || "服务端默认") + "）"
        : "由 config.toml 的 clipboard.seconds 决定"),
    ].forEach((pair) => {
      pair.forEach((node) => security.appendChild(node));
    });

    const writeHint = $("pv-settings-write-hint");
    if (writeHint) {
      writeHint.textContent = "网页里改主密码 / 重置恢复码的接口还没上线（此功能暂未就绪）。现在请用 pv passwd 与 pv recovery --reset。";
    }
    const changeBtn = $("pv-settings-change-password");
    if (changeBtn) changeBtn.disabled = true;
    const resetBtn = $("pv-settings-reset-recovery");
    if (resetBtn) resetBtn.disabled = true;

    const inbox = $("pv-settings-inbox");
    clearNode(inbox);
    const inboxInfo = session.inbox || null;
    [
      kvRow("inbox 目录", inboxInfo && inboxInfo.dir ? String(inboxInfo.dir) : "服务端没报上来"),
      kvRow("是否监听", inboxInfo && inboxInfo.watching ? "正在监听" : "未监听"),
      kvRow("扫描间隔", inboxInfo && inboxInfo.interval ? num(inboxInfo.interval, 0) + " 秒" : "未知"),
      kvRow("默认重复策略", "提交时才选（跳过 / 覆盖 / 追加），只对这一批生效，不写盘"),
    ].forEach((pair) => {
      pair.forEach((node) => inbox.appendChild(node));
    });

    await renderMcpBlock();

    const paths = $("pv-settings-paths");
    clearNode(paths);
    const dir = vaultDirGuess();
    [
      kvRow("库目录", dir || "未知（服务端只报了 inbox 目录）"),
      kvRow("快照目录", dir ? dir + "\\snapshots" : "未知"),
      kvRow("服务地址", session.port ? "http://127.0.0.1:" + session.port : "未知"),
    ].forEach((pair) => {
      pair.forEach((node) => paths.appendChild(node));
    });

    const danger = $("pv-settings-danger");
    clearNode(danger);
    [
      kvRow("改主密码", "会重写头部密钥封装，需要当前主密码。命令行：pv passwd"),
      kvRow("重置恢复码", "旧恢复码立刻失效。命令行：pv recovery --reset"),
    ].forEach((pair) => {
      pair.forEach((node) => danger.appendChild(node));
    });
  }

  /* ================================================================ 13. SSE */
  function parseEvent(event) {
    try {
      const data = JSON.parse(event.data || "{}");
      return data && typeof data === "object" ? data : {};
    } catch (exc) {
      return {};
    }
  }

  function connectEvents() {
    closeEvents();
    if (!("EventSource" in window)) {
      startPolling();
      return;
    }
    let source;
    try {
      source = new EventSource("/api/events");
    } catch (exc) {
      startPolling();
      return;
    }
    state.sse = source;

    source.addEventListener("open", () => {
      setSync("已连接");
      stopPolling();
    });

    source.addEventListener("session", (event) => {
      const data = parseEvent(event);
      if (!data || data.unlocked === undefined) {
        refreshSession({ silent: true });
        return;
      }
      applySession(data).catch(() => {
        /* 静默：SSE 会话刷新失败不该弹框 */
      });
    });

    source.addEventListener("revision", (event) => {
      const data = parseEvent(event);
      // 先把修订号落到 session 上，再刷列表 —— 顺序反了会让「修订 N」显示成旧值
      state.revision = num(data.revision, state.revision);
      if (state.session) {
        state.session.revision = state.revision;
        state.session.count = num(data.count, state.session.count);
      }
      const delta = num(data.delta, 0);
      if (delta > 0) toast("已同步（+" + delta + " 条）");
      else if (delta < 0) toast("已同步（" + delta + " 条）");
      else toast("已同步");
      // 静默刷新：列表 + 标签 + 当前详情；正在输入时不打断焦点
      const typing = document.activeElement && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      loadRecords({ reset: true }).then(() => {
        if (state.selectedId && !typing) selectRecord(state.selectedId);
      });
      loadTags();
      renderTopbar();
      if (state.page === "health") loadHealth();
      if (state.page === "staging") loadStaging();
    });

    source.addEventListener("staging", () => {
      refreshStagingBadge();
      if (state.page === "staging") loadStaging();
    });

    source.addEventListener("agent", (event) => {
      const data = parseEvent(event);
      if (state.session) {
        state.session.agent = data.status || data.agent || state.session.agent;
        renderTopbar();
      }
    });

    source.addEventListener("lag", () => {
      // 事件队列满了：语义是「你落后了，全量刷一次」
      refreshSession({ silent: true });
      loadRecords({ reset: true });
    });

    source.addEventListener("error", () => {
      // EventSource 自己会重连；这里只负责在等待期间别让界面变成死水
      setSync("正在重连…");
      startPolling();
    });
  }

  function closeEvents() {
    if (state.sse) {
      try {
        state.sse.close();
      } catch (exc) {
        /* 忽略 */
      }
      state.sse = null;
    }
  }

  function startPolling() {
    if (state.pollTimer) return;
    state.pollTimer = window.setInterval(() => {
      refreshSession({ silent: true }).then(() => {
        if (state.session && state.session.unlocked) {
          loadRecords({ reset: true });
          refreshStagingBadge();
        }
      }).catch(() => {
        setSync("连不上服务");
      });
    }, POLL_MS);
  }

  function stopPolling() {
    if (!state.pollTimer) return;
    window.clearInterval(state.pollTimer);
    state.pollTimer = 0;
  }

  /* =========================================================== 14. 事件绑定 */
  const onSearchInput = debounce(() => {
    const input = $("pv-search-input");
    state.query = input ? input.value.trim() : "";
    loadRecords({ reset: true });
  }, SEARCH_DEBOUNCE_MS);

  function bindOnce() {
    state.editorId = (function () {
      try {
        const existing = sessionStorage.getItem("pv.editorId");
        if (existing) return existing;
        const made = (window.crypto && window.crypto.randomUUID) ? window.crypto.randomUUID() : "ed-" + Date.now() + "-" + Math.random().toString(16).slice(2);
        sessionStorage.setItem("pv.editorId", made);
        return made;
      } catch (exc) {
        return "ed-" + Date.now() + "-" + Math.random().toString(16).slice(2);
      }
    })();

    // ---- 解锁视图
    const unlockForm = $("pv-unlock-form");
    if (unlockForm) {
      unlockForm.addEventListener("submit", (event) => {
        event.preventDefault();
        submitUnlock("password");
      });
    }
    const recoverySubmit = $("pv-recovery-submit");
    if (recoverySubmit) recoverySubmit.addEventListener("click", () => submitUnlock("recovery"));
    const recoveryInput = $("pv-recovery");
    if (recoveryInput) {
      recoveryInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          submitUnlock("recovery");
        }
      });
    }
    const dpapi = $("pv-dpapi");
    if (dpapi) dpapi.addEventListener("click", () => submitUnlock("dpapi"));

    // ---- 顶栏
    const toggleSide = $("pv-toggle-sidebar");
    if (toggleSide) {
      toggleSide.addEventListener("click", () => {
        state.sideCollapsed = !state.sideCollapsed;
        const main = $("pv-main");
        if (main) main.dataset.side = state.sideCollapsed ? "collapsed" : "expanded";
        toggleSide.setAttribute("aria-expanded", state.sideCollapsed ? "false" : "true");
      });
    }
    const lockBtn = $("pv-lock-now");
    if (lockBtn) lockBtn.addEventListener("click", lockNow);

    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-pref]"), (button) => {
      button.addEventListener("click", () => {
        const pref = button.dataset.themePref;
        state.themePref = pref;
        applyTheme(pref);
        try {
          localStorage.setItem(THEME_KEY, pref);
        } catch (exc) {
          /* 存不了就算了，本次会话内仍生效 */
        }
        renderThemeButtons();
      });
    });

    // ---- 左栏
    const search = $("pv-search-input");
    if (search) {
      search.addEventListener("input", onSearchInput);
      search.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          search.value = "";
          state.query = "";
          loadRecords({ reset: true });
          search.blur();
        }
      });
    }
    const newRecord = $("pv-new-record");
    if (newRecord) newRecord.addEventListener("click", () => openRecordDialog(null));

    const gotoStaging = $("pv-goto-staging");
    if (gotoStaging) gotoStaging.addEventListener("click", () => showPage("staging"));
    const gotoHealth = $("pv-goto-health");
    if (gotoHealth) gotoHealth.addEventListener("click", () => showPage("health"));
    const gotoSettings = $("pv-goto-settings");
    if (gotoSettings) gotoSettings.addEventListener("click", () => showPage("settings"));

    // ---- 列表（事件委托：行 hover 按钮 + 选中）
    const listNode = $("pv-list");
    if (listNode) {
      listNode.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const row = target.closest(".pv-row");
        if (!row) {
          if (target.closest(".pv-list-sentinel")) advanceList();
          return;
        }
        const id = row.dataset.id;
        const actionNode = target.closest("[data-action]");
        if (actionNode) {
          const action = actionNode.dataset.action;
          event.stopPropagation();
          if (action === "copy") {
            selectRecord(id);
            copyField(id, "password");
          } else if (action === "edit") {
            selectRecord(id, { focusTitle: false }).then(() => {
              if (state.detail) openRecordDialog(state.detail);
            });
          }
          return;
        }
        selectRecord(id);
      });
      listNode.addEventListener("dblclick", (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const row = target.closest(".pv-row");
        if (row) selectRecord(row.dataset.id, { focusTitle: true });
      });
      listNode.addEventListener("keydown", onListKeydown);
    }

    // ---- 详情
    const titleNode = $("pv-detail-title");
    if (titleNode) {
      titleNode.addEventListener("click", startTitleEdit);
      titleNode.addEventListener("focus", () => {
        /* 只保留焦点环，不自动进编辑态 */
      });
      titleNode.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          startTitleEdit();
        }
      });
    }
    const titleInput = $("pv-detail-title-input");
    if (titleInput) {
      titleInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commitTitleEdit();
        } else if (event.key === "Escape") {
          event.preventDefault();
          cancelTitleEdit();
        }
      });
      titleInput.addEventListener("blur", () => {
        if (!titleInput.hidden) commitTitleEdit();
      });
    }

    const copyPassword = $("pv-copy-password");
    if (copyPassword) copyPassword.addEventListener("click", () => copyField(state.selectedId, "password"));
    const copyUsername = $("pv-copy-username");
    if (copyUsername) copyUsername.addEventListener("click", () => copyField(state.selectedId, "username"));
    const openUrl = $("pv-open-url");
    if (openUrl) {
      openUrl.addEventListener("click", () => {
        const href = state.detail ? safeHref(state.detail.url) : "";
        if (!href) {
          toast("这条记录没有可打开的网址。", "warn");
          return;
        }
        window.open(href, "_blank", "noreferrer,noopener");
      });
    }
    const editRecord = $("pv-edit-record");
    if (editRecord) editRecord.addEventListener("click", () => {
      if (state.detail) openRecordDialog(state.detail);
    });
    const deleteRecord = $("pv-delete-record");
    if (deleteRecord) deleteRecord.addEventListener("click", openDeleteDialog);

    // ---- 待整理
    const acceptAll = $("pv-accept-all");
    if (acceptAll) acceptAll.addEventListener("click", () => toggleAcceptAll());
    const commitBtn = $("pv-commit");
    if (commitBtn) commitBtn.addEventListener("click", () => commitBatch());
    Array.prototype.forEach.call(document.querySelectorAll("#pv-mode [data-mode]"), (button) => {
      button.addEventListener("click", () => {
        state.staging.mode = button.dataset.mode;
        updateFoot();
      });
    });
    const discardBtn = $("pv-discard");
    if (discardBtn) discardBtn.addEventListener("click", () => discardBatch());
    const rollbackBtn = $("pv-rollback");
    if (rollbackBtn) rollbackBtn.addEventListener("click", () => rollbackBatch());
    const openInbox = $("pv-open-inbox");
    if (openInbox) openInbox.addEventListener("click", () => openInboxFolder());
    const pickFile = $("pv-pick-file");
    const fileInput = $("pv-file-input");
    if (pickFile && fileInput) {
      pickFile.addEventListener("click", () => fileInput.click());
      fileInput.addEventListener("change", () => {
        if (fileInput.files) uploadFiles(fileInput.files);
        fileInput.value = "";
      });
    }

    // ---- 设置
    const openVaultDir = $("pv-open-vault-dir");
    if (openVaultDir) {
      openVaultDir.addEventListener("click", async () => {
        const dir = vaultDirGuess();
        if (!dir) {
          toast("还没拿到库目录。", "warn");
          return;
        }
        const ok = await copyText(dir);
        toast(ok ? "库目录路径已复制，粘到资源管理器就能打开。" : "浏览器不让写剪贴板，路径是：", ok ? "info" : "warn", dir);
      });
    }
    const openSnapDir = $("pv-open-snapshot-dir");
    if (openSnapDir) {
      openSnapDir.addEventListener("click", async () => {
        const dir = vaultDirGuess();
        if (!dir) {
          toast("还没拿到库目录。", "warn");
          return;
        }
        const full = dir + "\\snapshots";
        const ok = await copyText(full);
        toast(ok ? "快照目录路径已复制。" : "浏览器不让写剪贴板，路径是：", ok ? "info" : "warn", full);
      });
    }

    // ---- 全局键盘
    document.addEventListener("keydown", onGlobalKeydown);
    // ---- 拖拽
    initDragDrop();
    // ---- 走的时候收摊（SSE 占连接，DESIGN R8）
    window.addEventListener("beforeunload", () => {
      closeEvents();
      stopPolling();
      const staging = state.staging;
      if (staging.currentId && staging.editorHeld && navigator.sendBeacon) {
        try {
          navigator.sendBeacon(
            "/api/staging/" + encodeURIComponent(staging.currentId) + "/edit",
            new Blob([JSON.stringify({ editor_id: state.editorId, action: "end" })], { type: "application/json" })
          );
        } catch (exc) {
          /* 走不走都无所谓，服务端有超时回收 */
        }
      }
    });
    // ---- 定时器：自锁倒计时 + 每秒刷新顶栏
    window.setInterval(() => {
      if (state.session && state.session.unlocked) updateLockLabel();
    }, 1000);
  }

  function renderThemeButtons() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-theme-pref]"), (button) => {
      button.setAttribute("aria-pressed", button.dataset.themePref === state.themePref ? "true" : "false");
    });
  }

  function onListKeydown(event) {
    const key = event.key;
    if (key === "ArrowDown") {
      event.preventDefault();
      moveSelection(1);
      return;
    }
    if (key === "ArrowUp") {
      event.preventDefault();
      moveSelection(-1);
      return;
    }
    if (key === "Enter") {
      event.preventDefault();
      if (!state.selectedId) {
        moveSelection(1);
        return;
      }
      if (event.ctrlKey || event.metaKey) focusDetailTitle();
      else copyField(state.selectedId, "password");
      return;
    }
    if (key === "Escape") {
      state.query = "";
      const search = $("pv-search-input");
      if (search) search.value = "";
      loadRecords({ reset: true });
    }
  }

  function isTypingTarget(target) {
    if (!target || !target.tagName) return false;
    const tag = target.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
    return !!target.isContentEditable;
  }

  function onGlobalKeydown(event) {
    const key = (event.key || "").toLowerCase();
    // Ctrl+K：聚焦搜索
    if ((event.ctrlKey || event.metaKey) && key === "k") {
      event.preventDefault();
      const search = $("pv-search-input");
      if (search) {
        if (state.page !== "records") showPage("records");
        search.focus();
        search.select();
      }
      return;
    }
    // Ctrl+Shift+C：复制选中记录的密码（焦点在输入框里时不拦截）
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && key === "c") {
      if (isTypingTarget(event.target)) return;
      if (state.page !== "records" || !state.selectedId) return;
      event.preventDefault();
      copyField(state.selectedId, "password");
      return;
    }
    if (key === "escape") {
      if (modalState.open) {
        event.preventDefault();
        closeModal();
        return;
      }
      const search = $("pv-search-input");
      if (document.activeElement === search && search && search.value) {
        search.value = "";
        state.query = "";
        loadRecords({ reset: true });
        return;
      }
    }
  }

  function initDragDrop() {
    let depth = 0;
    const veil = $("pv-dropveil");

    function showVeil(show) {
      if (!veil) return;
      veil.hidden = !show;
    }

    window.addEventListener("dragenter", (event) => {
      if (!state.session || !state.session.unlocked) return;
      if (!event.dataTransfer || Array.prototype.indexOf.call(event.dataTransfer.types || [], "Files") < 0) return;
      depth += 1;
      showVeil(true);
    });
    window.addEventListener("dragover", (event) => {
      if (!state.session || !state.session.unlocked) return;
      event.preventDefault();
      const zone = $("pv-dropzone");
      if (zone) zone.dataset.active = "true";
    });
    window.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (depth === 0) {
        showVeil(false);
        const zone = $("pv-dropzone");
        if (zone) zone.dataset.active = "false";
      }
    });
    window.addEventListener("drop", (event) => {
      const zone = $("pv-dropzone");
      if (zone) zone.dataset.active = "false";
      showVeil(false);
      depth = 0;
      if (!state.session || !state.session.unlocked) return;
      if (!event.dataTransfer || !event.dataTransfer.files || !event.dataTransfer.files.length) return;
      event.preventDefault();
      uploadFiles(event.dataTransfer.files);
    });
  }

  /* ================================================================= 15. 启动 */
  async function boot() {
    renderThemeButtons();
    renderDetailEmpty();
    bindOnce();
    setPageChrome();
    renderViews();
    progressNode();
    try {
      const payload = await apiGet("/api/session");
      await applySession(payload, { force: true });
    } catch (exc) {
      setMode("unlock");
      showUnlockError(describeError(exc), exc instanceof ApiError ? exc.hint : "");
      setSync("连不上服务");
    }
    connectEvents();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      boot().catch((exc) => {
        // 最后一道网：启动失败也要给出可读信息，不留白屏
        setMode("unlock");
        showUnlockError("界面启动时出错了：" + (exc && exc.message ? exc.message : String(exc)));
      });
    });
  } else {
    boot().catch((exc) => {
      setMode("unlock");
      showUnlockError("界面启动时出错了：" + (exc && exc.message ? exc.message : String(exc)));
    });
  }
})();
