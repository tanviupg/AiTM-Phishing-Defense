/**
 * FIDO2/Passkey Defense, Session Containment & Hardening Checklist Page (Module 3 Integration).
 */
import { apiClient } from "../services/apiClient.js";
import { escapeHtml, severityBadgeClass, showToast, statusBadgeClass } from "../components/utils.js";

export async function renderHardeningPage(container) {
  container.innerHTML = `<div class="card"><div class="card-subtitle">Loading Module 3 FIDO2 &amp; hardening intelligence...</div></div>`;

  let overview;
  let sessionsRes;
  try {
    [overview, sessionsRes] = await Promise.all([
      apiClient.getHardeningOverview(),
      apiClient.getSessions(),
    ]);
  } catch (err) {
    container.innerHTML = `<div class="card"><div class="badge badge-critical">${escapeHtml(err.message)}</div></div>`;
    return;
  }

  const methods = overview.auth_methods || [];
  const origin = overview.origin_binding || {};
  const tokenBinding = overview.token_binding || {};
  const checklist = overview.checklist || [];
  const sessions = sessionsRes.items || [];

  container.innerHTML = `
    <!-- Origin Binding & Token Binding -->
    <section class="grid-2">
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">${escapeHtml(origin.title || "FIDO2 / WebAuthn Origin Binding")}</div>
            <div class="card-subtitle">Why Passkeys mathematically neutralize AiTM reverse proxies (Module 3)</div>
          </div>
          <span class="badge badge-low">PHISHING-RESISTANT</span>
        </div>
        <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:0.85rem;">
          ${escapeHtml(origin.executive_summary || "FIDO2 cryptographically binds authentication signatures to the genuine domain in the browser address bar.")}
        </p>
        <div style="display:flex; flex-direction:column; gap:0.5rem;">
          ${(origin.protocol_breakdown || [])
            .map(
              (st) => `
            <div class="threat-reason-item">
              <div style="font-size:0.75rem; color:var(--cyan); font-weight:700;">Step ${st.step}: ${escapeHtml(st.name)} (${escapeHtml(st.actor)})</div>
              <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.2rem;">${escapeHtml(st.description)}</div>
            </div>`
            )
            .join("")}
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">${escapeHtml(tokenBinding.title || "Cryptographic Token Binding (DPoP / mTLS)")}</div>
            <div class="card-subtitle">Neutralizing stolen session cookies &amp; bearer tokens</div>
          </div>
          <span class="badge badge-purple">RFC 9449 / 8705</span>
        </div>
        <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:0.85rem;">
          ${escapeHtml(tokenBinding.executive_summary || "Proof-of-possession binds session tokens to a client private key.")}
        </p>
        <div style="display:flex; flex-direction:column; gap:0.65rem;">
          ${(tokenBinding.mechanisms || [])
            .map(
              (m) => `
            <div class="threat-box">
              <div style="font-weight:700; font-size:0.85rem; color:var(--cyan);">${escapeHtml(m.standard)}</div>
              <div style="font-size:0.8rem; color:var(--text-secondary);">${escapeHtml(m.operation)}</div>
              <div style="font-size:0.78rem; color:var(--emerald);"><strong>AiTM Defense:</strong> ${escapeHtml(m.aitm_neutralization)}</div>
            </div>`
            )
            .join("")}
        </div>
      </div>
    </section>

    <!-- Synthetic Sessions & Containment -->
    <section class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Synthetic Session Containment (Module 3)</div>
          <div class="card-subtitle">Revoke compromised synthetic sessions and test HTTP 401 replay rejection</div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Session ID</th>
              <th>User Alias</th>
              <th>Source IP</th>
              <th>Client Context</th>
              <th>Status</th>
              <th>Containment Actions</th>
            </tr>
          </thead>
          <tbody>
            ${
              sessions.length === 0
                ? `<tr><td colspan="6" style="color:var(--text-muted)">No synthetic sessions recorded.</td></tr>`
                : sessions
                    .map((s) => {
                      const revoked = s.status === "revoked";
                      return `
                <tr>
                  <td class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(s.session_id)}</td>
                  <td>${escapeHtml(s.user_alias)}</td>
                  <td class="mono">${escapeHtml(s.source_ip)}</td>
                  <td style="font-size:0.78rem; color:var(--text-secondary); max-width:260px;">${escapeHtml(s.client_context)}</td>
                  <td><span class="badge ${revoked ? "badge-purple" : "badge-low"}">${escapeHtml(String(s.status).toUpperCase())}</span></td>
                  <td>
                    <div class="toolbar">
                      ${!revoked ? `<button class="btn btn-danger btn-sm sess-revoke-btn" data-id="${escapeHtml(s.session_id)}">Revoke Token</button>` : ""}
                      <button class="btn btn-secondary btn-sm sess-test-btn" data-id="${escapeHtml(s.session_id)}">Test Access</button>
                    </div>
                  </td>
                </tr>`;
                    })
                    .join("")
            }
          </tbody>
        </table>
      </div>
    </section>

    <!-- Auth Method Resistance Matrix -->
    <section class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Authentication Factor AiTM Resistance Matrix</div>
          <div class="card-subtitle">Comparison of legacy MFA vs. phishing-resistant FIDO2 / Passkeys (Module 3 Knowledge Base)</div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Authentication Method</th>
              <th>NIST AAL</th>
              <th>AiTM Resistance</th>
              <th>Origin Bound</th>
              <th>Recommended Action</th>
            </tr>
          </thead>
          <tbody>
            ${methods
              .map((m) => {
                const cls =
                  m.resistance_rating === "PHISHING_RESISTANT"
                    ? "badge-low"
                    : m.resistance_rating === "PARTIALLY_RESISTANT"
                    ? "badge-medium"
                    : "badge-critical";
                return `
              <tr>
                <td>
                  <strong>${escapeHtml(m.display_name)}</strong>
                  <div style="font-size:0.76rem; color:var(--text-secondary);">${escapeHtml(m.aitm_resistance_explanation)}</div>
                </td>
                <td class="mono">${escapeHtml(m.nist_aal_level)}</td>
                <td><span class="badge ${cls}">${escapeHtml(m.resistance_rating)}</span></td>
                <td>${m.origin_bound ? `<span style="color:var(--emerald); font-weight:700;">YES</span>` : `<span style="color:var(--crimson);">NO</span>`}</td>
                <td style="font-size:0.79rem; color:var(--text-secondary);">${escapeHtml(m.recommended_action)}</td>
              </tr>`;
              })
              .join("")}
          </tbody>
        </table>
      </div>
    </section>

    <!-- CISA / NIST Hardening Checklist -->
    <section class="card">
      <div class="card-header">
        <div>
          <div class="card-title">CISA &amp; NIST SP 800-63B Hardening Checklist</div>
          <div class="card-subtitle">Update control verification status directly in the Module 3 SQLite checklist</div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Hardening Control</th>
              <th>Priority</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${checklist
              .map(
                (item) => `
              <tr>
                <td class="mono" style="color:var(--cyan); font-weight:700;">${escapeHtml(item.item_id)}</td>
                <td>
                  <strong>${escapeHtml(item.title)}</strong>
                  <div style="font-size:0.77rem; color:var(--text-secondary);">${escapeHtml(item.mitigation_detail)}</div>
                </td>
                <td><span class="badge ${severityBadgeClass(item.priority)}">${escapeHtml(item.priority)}</span></td>
                <td>
                  <select class="select chk-status-select" data-id="${escapeHtml(item.item_id)}">
                    ${["Verified", "In progress", "Not assessed", "Not applicable"]
                      .map((st) => `<option value="${st}" ${item.status === st ? "selected" : ""}>${st}</option>`)
                      .join("")}
                  </select>
                </td>
              </tr>`
              )
              .join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;

  container.querySelectorAll(".sess-revoke-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const res = await apiClient.revokeSession(btn.dataset.id);
        showToast(res.message || `Session ${btn.dataset.id} revoked.`);
        renderHardeningPage(container);
      } catch (err) {
        showToast(`Error revoking session: ${err.message}`);
      }
    });
  });

  container.querySelectorAll(".sess-test-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const res = await apiClient.testSessionAccess(btn.dataset.id);
        showToast(
          res.status_code === 401
            ? `HTTP 401 BLOCKED: ${res.detail}`
            : `HTTP ${res.status_code}: ${res.detail}`,
          4500
        );
      } catch (err) {
        showToast(`Access test error: ${err.message}`);
      }
    });
  });

  container.querySelectorAll(".chk-status-select").forEach((sel) => {
    sel.addEventListener("change", async () => {
      try {
        await apiClient.updateChecklistItem(sel.dataset.id, sel.value);
        showToast(`Checklist ${sel.dataset.id} updated to "${sel.value}"`);
      } catch (err) {
        showToast(`Checklist update failed: ${err.message}`);
      }
    });
  });
}
