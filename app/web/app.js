const $ = (id) => document.getElementById(id);

let currentVersion = 0;
let pollTimer = null;

const STATUS_LABEL = {
  free: "空闲",
  offered: "已预留 (OFFER)",
  bound: "已确认 (ACK)",
  declined: "隔离中 (DECLINE)",
};

const ACTION_LABEL = {
  DHCPOFFER: "已返回 OFFER",
  DHCPACK: "已返回 ACK",
  DHCPNAK: "已返回 NAK（地址不可用）",
};

const VERDICT_LABEL = {
  trusted: "受信应答",
  rogue: "非授权应答",
  "spoofed-identifier": "冒用受信标识（仍属非授权）",
  "identity-mismatch": "身份/事务号不符（未采信）",
  malformed: "报文无法解析",
  "unexpected-message-type": "非 OFFER 报文",
  unverified: "未核实（无有效应答）",
};

const TARGET_STATE_LABEL = {
  pending: "等待应答",
  answered: "已收到应答",
  timeout: "超时",
  unverified: "未核实",
  error: "端点不可达",
};

const ROUND_STATUS_LABEL = {
  running: "进行中",
  completed: "已完成",
  cancelled: "已取消",
  timeout: "等待窗口结束",
};

function setHealth(ok, text) {
  const el = $("health");
  el.textContent = text;
  el.className = "health " + (ok ? "ok" : "bad");
}

function fmtRemaining(sec) {
  if (sec <= 0) return "0s";
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return m > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function renderPool(state) {
  const { config, stats, leases } = state;
  const byIp = new Map(leases.map((l) => [l.ip, l]));
  const start = ipToInt(config.pool_start);
  const end = ipToInt(config.pool_end);
  const chips = [];
  for (let n = start; n <= end; n++) {
    const ip = intToIp(n);
    const lease = byIp.get(ip);
    const status = lease ? lease.status : "free";
    let meta = STATUS_LABEL[status];
    if (lease) {
      const who = lease.hostname || lease.client_mac || lease.client_key;
      meta += ` · ${who} · ${fmtRemaining(lease.remaining_seconds)}`;
    }
    chips.push(`<div class="chip ${status}"><span class="ip">${esc(ip)}</span><span class="meta">${esc(meta)}</span></div>`);
  }
  $("pool").innerHTML = chips.join("");
  $("config").innerHTML = [
    `<span>范围 <b>${esc(config.pool_start)} – ${esc(config.pool_end)}</b></span>`,
    `<span>子网 <b>${esc(config.subnet_mask)}</b></span>`,
    `<span>路由 <b>${esc(config.router)}</b></span>`,
    `<span>服务器 <b>${esc(config.server_id)}</b></span>`,
    `<span>租期 <b>${config.lease_time}s</b></span>`,
    `<span>OFFER 有效 <b>${config.offer_ttl}s</b></span>`,
    `<span>UDP <b>${config.udp_port}</b></span>`,
    `<span>空闲 <b>${stats.free}/${stats.pool_size}</b></span>`,
  ].join("");
}

function ipToInt(ip) {
  return ip.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
}
function intToIp(n) {
  return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");
}

function renderLeases(leases) {
  $("lease-count").textContent = `${leases.length} 条`;
  if (!leases.length) {
    $("leases").innerHTML = `<tr><td colspan="7" class="empty">暂无预留或租约</td></tr>`;
    return;
  }
  $("leases").innerHTML = leases.map((l) => `
    <tr>
      <td>${esc(l.ip)}</td>
      <td><span class="tag ${esc(l.status)}">${esc(STATUS_LABEL[l.status] || l.status)}</span></td>
      <td>${esc(l.client_key)}</td>
      <td>${esc(l.client_mac || "—")}</td>
      <td>${esc(l.hostname || "—")}</td>
      <td>${esc(fmtRemaining(l.remaining_seconds))}</td>
      <td>${esc(l.updated_at)}</td>
    </tr>`).join("");
}

function renderEvents(events) {
  if (!events.length) {
    $("events").innerHTML = `<tr><td colspan="6" class="empty">暂无事件</td></tr>`;
    return;
  }
  $("events").innerHTML = events.map((e) => `
    <tr>
      <td>${esc(e.at)}</td>
      <td>${esc(e.category)}</td>
      <td>${esc(e.message_type || "—")}</td>
      <td>${esc(e.ip || "—")}</td>
      <td>${esc(e.client_key || "—")}</td>
      <td class="detail">${esc(JSON.stringify(e.detail))}</td>
    </tr>`).join("");
}

async function refresh() {
  try {
    const res = await fetch("/api/state?ts=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const state = await res.json();
    currentVersion = state.version;
    setHealth(true, `服务正常 · UDP ${state.config.udp_port} · 空闲 ${state.stats.free}/${state.stats.pool_size}`);
    renderPool(state);
    renderLeases(state.leases);
    renderEvents(state.events);
    renderProbe(state.probe);
  } catch (err) {
    setHealth(false, "服务不可达: " + err.message);
  }
}

// -- directed probe -------------------------------------------------------

function renderProbe(probe) {
  if (!probe) return;
  const endpoints = probe.endpoints || [];
  const checked = new Set(
    Array.from(document.querySelectorAll(".probe-ep:checked")).map((el) => el.value)
  );
  if (!endpoints.length) {
    $("probe-endpoints").innerHTML =
      `<span class="empty">尚未登记端点；在下方表单登记，或使用 Compose 种子自动登记。</span>`;
  } else {
    $("probe-endpoints").innerHTML = endpoints.map((ep) => `
      <label class="endpoint-row">
        <input type="checkbox" class="probe-ep" value="${ep.id}" ${checked.has(String(ep.id)) ? "checked" : ""}>
        <span class="ep-name">${esc(ep.name)}</span>
        <span class="verdict ${ep.trusted ? "trusted" : "rogue"}">${ep.trusted ? "受信" : "非受信"}</span>
        <span class="ep-addr">${esc(ep.host)}:${ep.port}</span>
        <span class="ep-addr">SID: ${esc(ep.expected_server_id || "—")}</span>
        <button type="button" class="ghost probe-del" data-id="${ep.id}" style="padding:3px 10px">删除</button>
        <span class="ep-note">${esc(ep.note || "")}</span>
      </label>`).join("");
  }
  const rounds = probe.rounds || [];
  $("probe-round-count").textContent = `${rounds.length} 轮（最近）`;
  renderRoundSummaries(rounds);
  if (rounds.some((r) => r.status === "running")) {
    // Keep evidence updating while a round is in flight.
    setTimeout(refreshRunningRound, 700);
  }
}

function renderRoundSummaries(rounds) {
  if (!rounds.length) {
    $("probe-rounds").innerHTML = `<p class="empty">还没有探测轮次。</p>`;
    return;
  }
  $("probe-rounds").innerHTML = rounds
    .map((r) => `<div class="round-block ${esc(r.status)}" data-round="${r.id}">
      <div class="round-head">
        <span>轮次 <b>#${r.id}</b></span>
        <span>状态 <span class="verdict ${esc(r.status)}">${esc(ROUND_STATUS_LABEL[r.status] || r.status)}</span></span>
        <span>XID <b>${esc(r.xid)}</b></span>
        <span>探测身份 <b>${esc(r.mac)}</b></span>
        <span>创建 <b>${esc(r.created_at)}</b></span>
        <span>${esc(r.reason || "")}</span>
        <span class="round-detail-slot">${
          r.status === "running"
            ? `<button type="button" class="danger probe-cancel" data-round="${r.id}" style="padding:4px 12px">取消本轮</button>`
            : ""
        }</span>
      </div>
      <div class="round-evidence-slot"><span class="empty">证据加载中…</span></div>
    </div>`)
    .join("");
  rounds.forEach((r) => loadRoundDetail(r.id));
}

async function loadRoundDetail(roundId) {
  try {
    const res = await fetch(`/api/probe/rounds/${roundId}`, { cache: "no-store" });
    if (!res.ok) return;
    const detail = await res.json();
    const block = document.querySelector(`.round-block[data-round="${roundId}"]`);
    if (!block) return;
    block.querySelector(".round-evidence-slot").innerHTML = renderEvidence(detail);
  } catch (_) {
    /* refreshed on next poll */
  }
}

function renderEvidence(detail) {
  const rows = [];
  for (const target of detail.targets) {
    if (!target.replies.length) {
      rows.push(`<tr>
        <td>${esc(target.name)}<br><span class="ep-addr">${esc(target.host)}:${target.port}</span></td>
        <td><span class="verdict ${esc(target.state)}">${esc(TARGET_STATE_LABEL[target.state] || target.state)}</span></td>
        <td>—</td><td>—</td><td>—</td><td>—</td>
        <td class="detail">${target.state === "unverified" ? "窗口内未取得与本轮 XID/身份匹配的应答" : "等待应答或端点不可达"}</td>
      </tr>`);
      continue;
    }
    for (const reply of target.replies) {
      rows.push(`<tr>
        <td>${esc(target.name)}<br><span class="ep-addr">${esc(reply.source)}</span></td>
        <td><span class="verdict ${esc(reply.verdict)}">${esc(VERDICT_LABEL[reply.verdict] || reply.verdict)}</span></td>
        <td>${esc(reply.message_type || "—")}</td>
        <td>${esc(reply.server_id || "—")}</td>
        <td>${esc(reply.yiaddr || "—")}</td>
        <td>${esc(reply.router || "—")}</td>
        <td class="detail">${esc(reply.reason)}</td>
      </tr>`);
    }
  }
  const withdrawn = detail.targets.flatMap((t) => t.withdrawn_ips || []);
  const cleanup = withdrawn.length
    ? `<p class="hint">本轮结束后已撤销本服务 OFFER 预留：${esc([...new Set(withdrawn)].join(", "))}（bound 租约未触碰）</p>`
    : "";
  return `${cleanup}
    <div class="table-wrap"><table>
      <thead><tr><th>应答来源</th><th>判定</th><th>报文</th><th>Server ID</th><th>拟分配地址</th><th>网关</th><th>判定依据</th></tr></thead>
      <tbody>${rows.join("")}</tbody>
    </table></div>`;
}

async function refreshRunningRound() {
  const running = document.querySelector(".round-block.running");
  if (!running) return;
  await loadRoundDetail(Number(running.dataset.round));
  const stillRunning = document.querySelector(".round-block.running");
  if (stillRunning) setTimeout(refreshRunningRound, 700);
  else refresh();
}

async function apiJson(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `HTTP ${res.status}`);
  return data;
}

$("probe-endpoints").addEventListener("click", async (e) => {
  const btn = e.target.closest(".probe-del");
  if (!btn) return;
  if (!confirm("删除该端点登记？")) return;
  try {
    const res = await fetch(`/api/probe/endpoints/${btn.dataset.id}`, { method: "DELETE" });
    if (!res.ok && res.status !== 204) throw new Error(`HTTP ${res.status}`);
    $("probe-status").textContent = "端点已删除";
    refresh();
  } catch (err) {
    $("probe-status").textContent = "删除失败: " + err.message;
  }
});

$("probe-endpoint-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const body = {
    name: $("ep-name").value.trim(),
    host: $("ep-host").value.trim(),
    port: Number($("ep-port").value.trim()),
    expected_server_id: $("ep-sid").value.trim() || null,
    trusted: $("ep-trusted").checked,
    note: $("ep-note").value.trim() || null,
  };
  try {
    await apiJson("/api/probe/endpoints", { method: "POST", body: JSON.stringify(body) });
    $("probe-status").textContent = `已登记端点 ${body.name}`;
    e.target.reset();
    refresh();
  } catch (err) {
    $("probe-status").textContent = "登记失败: " + err.message;
  }
});

$("probe-select-trusted").addEventListener("click", () => {
  document.querySelectorAll(".probe-ep").forEach((el) => {
    const row = el.closest(".endpoint-row");
    el.checked = row.querySelector(".verdict.trusted") !== null;
  });
});
$("probe-select-all").addEventListener("click", () => {
  document.querySelectorAll(".probe-ep").forEach((el) => { el.checked = true; });
});

$("probe-start").addEventListener("click", async () => {
  const ids = Array.from(document.querySelectorAll(".probe-ep:checked")).map((el) => Number(el.value));
  if (!ids.length) {
    $("probe-status").textContent = "请先勾选至少一个端点";
    return;
  }
  const btn = $("probe-start");
  btn.disabled = true;
  $("probe-status").textContent = "探测进行中（真实 DISCOVER 已发出）…";
  try {
    const detail = await apiJson("/api/probe/rounds", {
      method: "POST",
      body: JSON.stringify({ endpoint_ids: ids }),
    });
    $("probe-status").textContent = `第 #${detail.id} 轮已发起，XID ${detail.xid}，窗口 ${detail.timeout}s`;
    refresh();
  } catch (err) {
    $("probe-status").textContent = "发起失败: " + err.message;
  } finally {
    btn.disabled = false;
  }
});

$("probe-rounds").addEventListener("click", async (e) => {
  const btn = e.target.closest(".probe-cancel");
  if (!btn) return;
  btn.disabled = true;
  try {
    await apiJson(`/api/probe/rounds/${btn.dataset.round}/cancel`, { method: "POST" });
    $("probe-status").textContent = "已取消；已收证据保留，未应答端点标记为未核实";
    refresh();
  } catch (err) {
    $("probe-status").textContent = "取消失败: " + err.message;
    btn.disabled = false;
  }
});

async function longPoll() {
  try {
    const res = await fetch(`/api/state/wait?after=${currentVersion}`, { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      if (data.version !== currentVersion) refresh();
    }
  } catch (_) {
    /* retry below */
  } finally {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(longPoll, 1500);
  }
}

function updateTargetFields() {
  const custom = $("target").value === "custom";
  $("target_host").disabled = !custom;
  $("target_port").disabled = !custom;
}

function updateActionFields() {
  const kind = $("kind").value;
  const request = kind === "REQUEST";
  const release = kind === "RELEASE";
  $("requested_ip").disabled = !request;
  $("ciaddr").disabled = !(request || release);
}

function formBody() {
  const xidRaw = $("xid").value.trim();
  const portRaw = $("target_port").value.trim();
  const body = {
    kind: $("kind").value,
    mac: $("mac").value.trim(),
    hostname: $("hostname").value.trim() || null,
    requested_ip: $("requested_ip").value.trim() || null,
    ciaddr: $("ciaddr").value.trim() || null,
    server_id: $("server_id").value.trim() || null,
    use_client_id: $("use_client_id").checked,
    target: $("target").value,
  };
  if (xidRaw) body.xid = Number(xidRaw);
  if (body.target === "custom") {
    body.target_host = $("target_host").value.trim();
    body.target_port = portRaw ? Number(portRaw) : null;
  }
  return body;
}

async function sendPacket(body) {
  const status = $("sim-status");
  const buttons = document.querySelectorAll("#sim-form button");
  buttons.forEach((b) => (b.disabled = true));
  status.textContent = "发送中…";
  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    status.textContent = data.action
      ? ACTION_LABEL[data.action] || data.action
      : data.note;
    const box = $("sim-result");
    box.classList.remove("hidden");
    box.textContent = JSON.stringify(
      {
        目标: data.target,
        说明: data.note,
        动作: data.action,
        响应: data.reply,
        发送报文: data.sent_hex,
      },
      null,
      2
    );
    refresh();
  } catch (err) {
    status.textContent = "失败: " + err.message;
  } finally {
    buttons.forEach((b) => (b.disabled = false));
  }
}

$("kind").addEventListener("change", updateActionFields);
$("target").addEventListener("change", updateTargetFields);
$("sim-form").addEventListener("submit", (e) => {
  e.preventDefault();
  sendPacket(formBody());
});
$("quick-discover").addEventListener("click", () => {
  $("kind").value = "DISCOVER";
  updateActionFields();
  sendPacket(formBody());
});

updateTargetFields();
updateActionFields();
refresh().then(() => longPoll());
setInterval(refresh, 10000);
