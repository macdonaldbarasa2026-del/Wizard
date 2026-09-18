// Wizard Research Platform - Single Page Application Core
import { api } from "./services/api.js";

// Global App State
const state = {
  activeTab: "dashboard",
  capabilities: {},
  projects: [],
  selectedProject: null,
  analyses: [],
  selectedAnalysis: null,
  reResult: null,
  secResult: null,
  findings: [],
  auditLogs: [],
  loading: false,
  error: null,
};

// UI Rendering Functions
function renderApp() {
  const root = document.getElementById("app");
  root.innerHTML = `
    <div class="app-container">
      <!-- Sidebar Navigation -->
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-icon">⚡</div>
          <div>
            <div class="brand-title">WIZARD</div>
            <div class="brand-subtitle">CYBERSECURITY RESEARCH</div>
          </div>
        </div>
        <ul class="nav-list">
          <li class="nav-item ${state.activeTab === "dashboard" ? "active" : ""}" data-tab="dashboard">
            <span class="nav-icon">📊</span> Dashboard
          </li>
          <li class="nav-item ${state.activeTab === "projects" ? "active" : ""}" data-tab="projects">
            <span class="nav-icon">📁</span> Projects
          </li>
          <li class="nav-item ${state.activeTab === "re" ? "active" : ""}" data-tab="re">
            <span class="nav-icon">🔬</span> Reverse Engineering
          </li>
          <li class="nav-item ${state.activeTab === "security" ? "active" : ""}" data-tab="security">
            <span class="nav-icon">🛡️</span> Security Testing
          </li>
          <li class="nav-item ${state.activeTab === "findings" ? "active" : ""}" data-tab="findings">
            <span class="nav-icon">⚠️</span> Findings
          </li>
          <li class="nav-item ${state.activeTab === "reports" ? "active" : ""}" data-tab="reports">
            <span class="nav-icon">📑</span> Reports
          </li>
          <li class="nav-item ${state.activeTab === "settings" ? "active" : ""}" data-tab="settings">
            <span class="nav-icon">⚙️</span> Settings & Audit
          </li>
        </ul>
        <div class="sidebar-footer">
          <div>OS: Linux / Termux / Debian</div>
          <div style="margin-top: 4px; color: var(--accent-emerald);">● Backend Online</div>
        </div>
      </aside>

      <!-- Main Layout -->
      <main class="main-wrapper">
        <header class="top-bar">
          <div class="page-header-title" id="page-title">${getPageTitle(state.activeTab)}</div>
          <div class="top-bar-actions">
            <div class="cap-badge-group">
              <span class="cap-pill online">python: on</span>
              <span class="cap-pill ${state.capabilities.strings ? "online" : ""}">strings: ${state.capabilities.strings ? "on" : "off"}</span>
              <span class="cap-pill ${state.capabilities.objdump ? "online" : ""}">objdump: ${state.capabilities.objdump ? "on" : "off"}</span>
              <span class="cap-pill ${state.capabilities.readelf ? "online" : ""}">readelf: ${state.capabilities.readelf ? "on" : "off"}</span>
              <span class="cap-pill ${state.capabilities.yara ? "online" : ""}">yara: ${state.capabilities.yara ? "on" : "off"}</span>
            </div>
            <button class="btn btn-secondary" id="btn-refresh" style="padding: 6px 12px; font-size: 12px;">🔄 Refresh</button>
          </div>
        </header>

        <section class="content-area" id="content-container">
          ${renderTabContent(state.activeTab)}
        </section>
      </main>
    </div>

    <!-- Modals Container -->
    <div id="modal-container"></div>
  `;

  attachEventListeners();
}

function getPageTitle(tab) {
  switch (tab) {
    case "dashboard": return "Security Research Dashboard";
    case "projects": return "Target Projects & Archives";
    case "re": return "Binary Reverse Engineering Engine";
    case "security": return "Ethical Security Testing & Auditing";
    case "findings": return "Consolidated Vulnerability Findings";
    case "reports": return "Structured Assessment Reports";
    case "settings": return "Environment Capabilities & Audit Logs";
    default: return "Wizard Platform";
  }
}

function renderTabContent(tab) {
  switch (tab) {
    case "dashboard": return renderDashboard();
    case "projects": return renderProjects();
    case "re": return renderReverseEngineering();
    case "security": return renderSecurityTesting();
    case "findings": return renderFindings();
    case "reports": return renderReports();
    case "settings": return renderSettings();
    default: return `<div class="card">Unknown Tab</div>`;
  }
}

// ---------------------------------------------------------------------------
// 1. Dashboard View
// ---------------------------------------------------------------------------
function renderDashboard() {
  const totalFindings = state.findings.length;
  const criticalCount = state.findings.filter(f => f.severity === "critical").length;
  const highCount = state.findings.filter(f => f.severity === "high").length;
  const mediumCount = state.findings.filter(f => f.severity === "medium").length;
  const lowCount = state.findings.filter(f => f.severity === "low").length;
  const infoCount = state.findings.filter(f => f.severity === "info").length;

  return `
    <div class="grid-4">
      <div class="card">
        <div class="card-title">Active Projects</div>
        <div class="card-value">${state.projects.length}</div>
        <div class="card-subtitle">Imported analysis targets</div>
      </div>
      <div class="card">
        <div class="card-title">Completed Analyses</div>
        <div class="card-value">${state.analyses.length}</div>
        <div class="card-subtitle">AI & static engine runs</div>
      </div>
      <div class="card">
        <div class="card-title">Total Findings</div>
        <div class="card-value" style="color: var(--accent-cyan);">${totalFindings}</div>
        <div class="card-subtitle">Correlated observations</div>
      </div>
      <div class="card">
        <div class="card-title">Critical / High Severity</div>
        <div class="card-value" style="color: var(--sev-critical);">${criticalCount + highCount}</div>
        <div class="card-subtitle">Requires immediate triage</div>
      </div>
    </div>

    <!-- Severity Distribution Bar -->
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Findings Severity Breakdown</div>
      <div style="display: flex; height: 12px; border-radius: 6px; overflow: hidden; background: #0a0f1d; margin: 12px 0;">
        <div style="width: ${totalFindings ? (criticalCount / totalFindings) * 100 : 0}%; background: var(--sev-critical);" title="Critical: ${criticalCount}"></div>
        <div style="width: ${totalFindings ? (highCount / totalFindings) * 100 : 0}%; background: var(--sev-high);" title="High: ${highCount}"></div>
        <div style="width: ${totalFindings ? (mediumCount / totalFindings) * 100 : 0}%; background: var(--sev-medium);" title="Medium: ${mediumCount}"></div>
        <div style="width: ${totalFindings ? (lowCount / totalFindings) * 100 : 0}%; background: var(--sev-low);" title="Low: ${lowCount}"></div>
        <div style="width: ${totalFindings ? (infoCount / totalFindings) * 100 : 0}%; background: var(--sev-info);" title="Info: ${infoCount}"></div>
      </div>
      <div style="display: flex; gap: 12px; flex-wrap: wrap; font-size: 12px;">
        <span class="badge badge-critical">Critical: ${criticalCount}</span>
        <span class="badge badge-high">High: ${highCount}</span>
        <span class="badge badge-medium">Medium: ${mediumCount}</span>
        <span class="badge badge-low">Low: ${lowCount}</span>
        <span class="badge badge-info">Info: ${infoCount}</span>
      </div>
    </div>

    <!-- Quick Actions & Recent Activity -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
      <div class="card">
        <div class="card-title">Quick Actions</div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 12px;">
          <button class="btn btn-primary" id="btn-quick-new-project">➕ Create New Project</button>
          <button class="btn btn-secondary" onclick="switchTab('re')">🔬 Inspect Binary File</button>
          <button class="btn btn-secondary" onclick="switchTab('security')">🛡️ Run Ethical Security Scan</button>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Recent Projects</div>
        <div style="margin-top: 10px;">
          ${state.projects.length === 0 ? '<div style="color: var(--text-muted);">No projects created yet.</div>' : `
            <div class="table-container" style="margin-bottom: 0;">
              <table>
                <thead>
                  <tr>
                    <th>Project Name</th>
                    <th>Status</th>
                    <th>Files</th>
                  </tr>
                </thead>
                <tbody>
                  ${state.projects.slice(0, 4).map(p => `
                    <tr>
                      <td style="font-weight: 600; color: #fff;">${escapeHtml(p.name)}</td>
                      <td><span class="badge badge-info">${escapeHtml(p.status)}</span></td>
                      <td>${p.file_count || 0} files</td>
                    </tr>
                  `).join("")}
                </tbody>
              </table>
            </div>
          `}
        </div>
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// 2. Projects View
// ---------------------------------------------------------------------------
function renderProjects() {
  return `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
      <div>
        <h2 style="font-size: 16px; font-weight: 700;">Target Projects</h2>
        <p style="color: var(--text-secondary); font-size: 13px;">Manage source directories, archives, and targets for defensive analysis.</p>
      </div>
      <button class="btn btn-primary" id="btn-modal-create-project">➕ New Project</button>
    </div>

    ${state.projects.length === 0 ? `
      <div class="card" style="text-align: center; padding: 48px;">
        <div style="font-size: 36px; margin-bottom: 12px;">📁</div>
        <h3 style="font-size: 16px; margin-bottom: 8px;">No projects created yet</h3>
        <p style="color: var(--text-muted); margin-bottom: 20px;">Create a project and upload a zip archive containing target source code or binaries.</p>
        <button class="btn btn-primary" id="btn-empty-create-project">Create Project</button>
      </div>
    ` : `
      <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;">
        ${state.projects.map(p => `
          <div class="card" style="display: flex; flex-direction: column; justify-content: space-between;">
            <div>
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <h3 style="font-size: 15px; font-weight: 700; color: #fff;">${escapeHtml(p.name)}</h3>
                <span class="badge badge-${p.status === 'analyzed' ? 'low' : 'info'}">${escapeHtml(p.status)}</span>
              </div>
              <p style="color: var(--text-secondary); font-size: 12px; margin-bottom: 12px;">
                ${escapeHtml(p.description || "No description provided.")}
              </p>
              <div style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); margin-bottom: 14px;">
                <div>ID: ${p.id}</div>
                <div>Files: ${p.file_count || 0} (${formatBytes(p.total_bytes || 0)})</div>
                <div>Created: ${new Date(p.created_at).toLocaleString()}</div>
              </div>
            </div>

            <div style="display: flex; gap: 8px; flex-wrap: wrap; border-top: 1px solid var(--border-color); padding-top: 12px;">
              <label class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px; cursor: pointer;">
                📤 Upload ZIP
                <input type="file" accept=".zip" style="display: none;" onchange="handleArchiveUpload('${p.id}', this.files[0])">
              </label>
              <button class="btn btn-primary" style="font-size: 12px; padding: 6px 10px;" onclick="handleRunAnalysis('${p.id}')">⚡ Analyze</button>
              <button class="btn btn-secondary" style="font-size: 12px; padding: 6px 10px;" onclick="viewProjectReport('${p.id}')">📑 Report</button>
              <button class="btn btn-danger" style="font-size: 12px; padding: 6px 10px; margin-left: auto;" onclick="handleDeleteProject('${p.id}')">🗑️</button>
            </div>
          </div>
        `).join("")}
      </div>
    `}
  `;
}

// ---------------------------------------------------------------------------
// 3. Reverse Engineering View
// ---------------------------------------------------------------------------
function renderReverseEngineering() {
  const res = state.reResult;

  return `
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Defensive Binary & Artifact Inspection</div>
      <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
        Upload an executable binary (ELF, PE, Mach-O) or compiled artifact to inspect headers, section permissions, entropy, extracted strings, and suspicious API indicators.
      </p>
      
      <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">
        <label class="btn btn-primary" style="cursor: pointer;">
          🔬 Upload Binary Directly
          <input type="file" style="display: none;" onchange="handleDirectREUpload(this.files[0])">
        </label>
        <span style="color: var(--text-muted); font-size: 12px;">OR analyze an imported project binary:</span>
        <select class="form-select" id="re-project-select" style="width: auto; max-width: 250px;" onchange="handleProjectRESelect(this.value)">
          <option value="">-- Choose Project --</option>
          ${state.projects.map(p => `<option value="${p.id}">${escapeHtml(p.name)}</option>`).join("")}
        </select>
      </div>
    </div>

    ${res ? `
      <!-- Binary Metadata Card -->
      <div class="grid-4">
        <div class="card">
          <div class="card-title">Format & Type</div>
          <div class="card-value" style="font-size: 20px; color: var(--accent-cyan);">${escapeHtml(res.metadata?.format || "Generic")}</div>
          <div class="card-subtitle">${escapeHtml(res.metadata?.file_type || "N/A")}</div>
        </div>
        <div class="card">
          <div class="card-title">Architecture</div>
          <div class="card-value" style="font-size: 20px;">${escapeHtml(res.metadata?.architecture || "N/A")}</div>
          <div class="card-subtitle">${res.metadata?.bits || 0}-bit (${escapeHtml(res.metadata?.endian || "N/A")})</div>
        </div>
        <div class="card">
          <div class="card-title">Shannon Entropy</div>
          <div class="card-value" style="font-size: 20px; color: ${res.metadata?.entropy > 7.2 ? 'var(--sev-high)' : 'var(--accent-emerald)'};">
            ${res.metadata?.entropy ? res.metadata.entropy.toFixed(4) : "0.0000"} / 8.0
          </div>
          <div class="card-subtitle">${res.metadata?.entropy > 7.2 ? "⚠️ Suspicious Packing / Encrypted" : "Normal Code Distribution"}</div>
        </div>
        <div class="card">
          <div class="card-title">SHA-256 Digest</div>
          <div class="card-value" style="font-size: 11px; word-break: break-all; font-family: var(--font-mono);">
            ${res.metadata?.sha256 || "N/A"}
          </div>
          <div class="card-subtitle">Size: ${formatBytes(res.metadata?.size || 0)}</div>
        </div>
      </div>

      <!-- Security Hardening Flags -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="card-title">Binary Hardening Protections</div>
        <div style="display: flex; gap: 12px; margin-top: 8px;">
          <span class="badge ${res.metadata?.hardening?.pie ? 'badge-low' : 'badge-high'}">
            PIE: ${res.metadata?.hardening?.pie ? 'ENABLED' : 'DISABLED'}
          </span>
          <span class="badge ${res.metadata?.hardening?.nx !== false && res.metadata?.hardening?.dep_nx !== false ? 'badge-low' : 'badge-critical'}">
            NX / DEP: ${res.metadata?.hardening?.nx !== false && res.metadata?.hardening?.dep_nx !== false ? 'ENABLED' : 'DISABLED'}
          </span>
          <span class="badge ${res.metadata?.hardening?.aslr ? 'badge-low' : 'badge-info'}">
            ASLR: ${res.metadata?.hardening?.aslr ? 'ENABLED' : 'N/A'}
          </span>
        </div>
      </div>

      <!-- Sections Table -->
      ${res.metadata?.sections && res.metadata.sections.length > 0 ? `
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-title">Binary Sections (${res.metadata.sections.length})</div>
          <div class="table-container" style="margin-bottom: 0;">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Size</th>
                  <th>Virtual Address</th>
                  <th>Permissions</th>
                  <th>Entropy</th>
                  <th>Flags / Status</th>
                </tr>
              </thead>
              <tbody>
                ${res.metadata.sections.map(s => `
                  <tr>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: #fff;">${escapeHtml(s.name)}</td>
                    <td>${formatBytes(s.size)}</td>
                    <td style="font-family: var(--font-mono);">0x${(s.virtual_address || 0).toString(16)}</td>
                    <td>
                      <span style="font-family: var(--font-mono); font-weight: 700; color: ${s.writable && s.executable ? 'var(--sev-critical)' : 'var(--text-secondary)'};">
                        ${s.readable ? 'R' : '-'}${s.writable ? 'W' : '-'}${s.executable ? 'X' : '-'}
                      </span>
                    </td>
                    <td style="color: ${s.entropy > 7.2 ? 'var(--sev-high)' : 'inherit'};">${s.entropy ? s.entropy.toFixed(4) : "0.0"}</td>
                    <td>
                      ${s.suspicious ? `<span class="badge badge-high">⚠️ ${escapeHtml(s.suspicious_reason || "Suspicious")}</span>` : `<span class="badge badge-info">Normal</span>`}
                    </td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      ` : ''}

      <!-- Strings & Disassembly Explorer -->
      <div class="card" style="margin-bottom: 20px;">
        <div class="tab-list" id="re-subtabs">
          <button class="tab-btn active" onclick="switchSubtab('tab-apis')">Suspicious APIs (${res.strings?.suspicious_apis?.length || 0})</button>
          <button class="tab-btn" onclick="switchSubtab('tab-urls')">URLs & Endpoints (${res.strings?.urls?.length || 0})</button>
          <button class="tab-btn" onclick="switchSubtab('tab-ips')">IP Addresses (${res.strings?.ips?.length || 0})</button>
          <button class="tab-btn" onclick="switchSubtab('tab-paths')">System Paths (${res.strings?.paths?.length || 0})</button>
          <button class="tab-btn" onclick="switchSubtab('tab-disasm')">Disassembly (objdump)</button>
        </div>

        <div id="tab-apis" class="subtab-content">
          ${res.strings?.suspicious_apis?.length > 0 ? `
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
              ${res.strings.suspicious_apis.map(api => `<span class="badge badge-high" style="font-size: 12px;">${escapeHtml(api)}</span>`).join("")}
            </div>
          ` : '<div style="color: var(--text-muted);">No sensitive or process-manipulating APIs detected in strings.</div>'}
        </div>

        <div id="tab-urls" class="subtab-content" style="display: none;">
          ${res.strings?.urls?.length > 0 ? `
            <pre class="code-block">${res.strings.urls.map(u => escapeHtml(u)).join("\n")}</pre>
          ` : '<div style="color: var(--text-muted);">No embedded URLs found.</div>'}
        </div>

        <div id="tab-ips" class="subtab-content" style="display: none;">
          ${res.strings?.ips?.length > 0 ? `
            <pre class="code-block">${res.strings.ips.map(ip => escapeHtml(ip)).join("\n")}</pre>
          ` : '<div style="color: var(--text-muted);">No IP addresses found.</div>'}
        </div>

        <div id="tab-paths" class="subtab-content" style="display: none;">
          ${res.strings?.paths?.length > 0 ? `
            <pre class="code-block">${res.strings.paths.map(p => escapeHtml(p)).join("\n")}</pre>
          ` : '<div style="color: var(--text-muted);">No hardcoded system paths found.</div>'}
        </div>

        <div id="tab-disasm" class="subtab-content" style="display: none;">
          ${res.disassembly && res.disassembly.length > 0 ? `
            <pre class="code-block">${res.disassembly.map(l => escapeHtml(l)).join("\n")}</pre>
          ` : `
            <div style="color: var(--text-muted); padding: 12px; background: rgba(0,0,0,0.2); border-radius: 4px;">
              ${res.errors?.find(e => e.includes("objdump")) || "Disassembly requires objdump or radare2 installed on the host. Header analysis and string extraction were completed natively."}
            </div>
          `}
        </div>
      </div>

      <!-- Reverse Engineering Findings -->
      <div class="card">
        <div class="card-title">Reverse Engineering Findings (${res.findings?.length || 0})</div>
        ${res.findings && res.findings.length > 0 ? `
          <div>
            ${res.findings.map(f => renderFindingCard(f)).join("")}
          </div>
        ` : '<div style="color: var(--text-muted);">No security or structural flaws identified for this binary.</div>'}
      </div>
    ` : `
      <div class="card" style="text-align: center; padding: 36px; color: var(--text-muted);">
        Upload a binary file above or choose an imported project to view reverse engineering results.
      </div>
    `}
  `;
}

// ---------------------------------------------------------------------------
// 4. Security Testing View
// ---------------------------------------------------------------------------
function renderSecurityTesting() {
  const res = state.secResult;

  return `
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Ethical Defensive Security Testing</div>
      <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
        Perform authorized static and defensive security assessments against source code, configuration files, and dependencies.
      </p>

      <form id="sec-testing-form" onsubmit="handleSecurityFormSubmit(event)">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
          <div class="form-group">
            <label class="form-label">Target Project</label>
            <select class="form-select" id="sec-project-id" required>
              <option value="">-- Select Project --</option>
              ${state.projects.map(p => `<option value="${p.id}">${escapeHtml(p.name)} (${p.file_count || 0} files)</option>`).join("")}
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Target Scope Host / URL</label>
            <input type="text" class="form-input" id="sec-target" value="127.0.0.1:8000" placeholder="e.g. 127.0.0.1:8000 or localhost" required>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px;">
          <div class="form-group">
            <label class="form-label">Assessment Mode</label>
            <select class="form-select" id="sec-mode">
              <option value="lab">Lab Environment (Strict Localhost / Private)</option>
              <option value="defensive">Defensive Audit</option>
              <option value="audit">Static Source Code Audit</option>
            </select>
          </div>

          <div class="form-group" style="display: flex; align-items: center; padding-top: 24px;">
            <label style="display: flex; align-items: center; gap: 10px; cursor: pointer; color: #fff; font-weight: 600; font-size: 13px;">
              <input type="checkbox" id="sec-authorized" checked required style="width: 18px; height: 18px;">
              I confirm I own or have explicit authorization for this target.
            </label>
          </div>
        </div>

        <button type="submit" class="btn btn-primary" id="btn-run-sec">🛡️ Run Authorized Security Scan</button>
      </form>
    </div>

    ${res ? `
      <!-- Security Results Header -->
      <div class="grid-4">
        <div class="card">
          <div class="card-title">Scope Status</div>
          <div class="card-value" style="font-size: 16px; color: var(--accent-emerald);">AUTHORIZED</div>
          <div class="card-subtitle">${escapeHtml(res.scope || "Local imported project")}</div>
        </div>
        <div class="card">
          <div class="card-title">Total Findings</div>
          <div class="card-value" style="color: var(--accent-cyan);">${res.finding_count || 0}</div>
          <div class="card-subtitle">Detected vulnerabilities & flaws</div>
        </div>
        <div class="card">
          <div class="card-title">Vulnerable Dependencies</div>
          <div class="card-value" style="color: var(--sev-high);">${res.dependency_vulnerabilities?.length || 0}</div>
          <div class="card-subtitle">Known CVEs identified</div>
        </div>
        <div class="card">
          <div class="card-title">Config Issues</div>
          <div class="card-value" style="color: var(--sev-medium);">${res.configuration_issues?.length || 0}</div>
          <div class="card-subtitle">Exposed .env / permissions</div>
        </div>
      </div>

      <!-- Vulnerable Dependencies Table -->
      ${res.dependency_vulnerabilities?.length > 0 ? `
        <div class="card" style="margin-bottom: 20px;">
          <div class="card-title">Vulnerable Dependencies Detected</div>
          <div class="table-container" style="margin-bottom: 0;">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Vulnerability Advisory</th>
                  <th>CVE Reference</th>
                </tr>
              </thead>
              <tbody>
                ${res.dependency_vulnerabilities.map(dep => `
                  <tr>
                    <td style="font-weight: 700; color: #fff;">${escapeHtml(dep.package)}</td>
                    <td style="font-family: var(--font-mono);">${escapeHtml(dep.version)}</td>
                    <td>${escapeHtml(dep.description)}</td>
                    <td><span class="badge badge-high">${escapeHtml(dep.cve)}</span></td>
                  </tr>
                `).join("")}
              </tbody>
            </table>
          </div>
        </div>
      ` : ''}

      <!-- Findings List -->
      <div class="card">
        <div class="card-title">Security Findings Details (${res.findings?.length || 0})</div>
        ${res.findings && res.findings.length > 0 ? `
          <div style="margin-top: 12px;">
            ${res.findings.map(f => renderFindingCard(f)).join("")}
          </div>
        ` : '<div style="color: var(--text-muted); padding: 12px;">No security vulnerabilities identified.</div>'}
      </div>
    ` : `
      <div class="card" style="text-align: center; padding: 36px; color: var(--text-muted);">
        Select an authorized project and run an ethical security scan to review results.
      </div>
    `}
  `;
}

// ---------------------------------------------------------------------------
// 5. Findings View
// ---------------------------------------------------------------------------
function renderFindings() {
  return `
    <div class="card" style="margin-bottom: 20px;">
      <div style="display: flex; gap: 16px; align-items: center; justify-content: space-between; flex-wrap: wrap;">
        <div style="display: flex; gap: 8px; flex-wrap: wrap;">
          <button class="btn btn-secondary" onclick="filterFindings('all')">All (${state.findings.length})</button>
          <button class="btn btn-secondary" onclick="filterFindings('critical')">Critical</button>
          <button class="btn btn-secondary" onclick="filterFindings('high')">High</button>
          <button class="btn btn-secondary" onclick="filterFindings('medium')">Medium</button>
          <button class="btn btn-secondary" onclick="filterFindings('low')">Low</button>
          <button class="btn btn-secondary" onclick="filterFindings('info')">Info</button>
        </div>
        <input type="text" class="form-input" id="findings-search" placeholder="Search rules, files, descriptions..." style="max-width: 300px;" oninput="handleFindingsSearch(this.value)">
      </div>
    </div>

    <div id="findings-list-container">
      ${state.findings.length === 0 ? `
        <div class="card" style="text-align: center; padding: 48px; color: var(--text-muted);">
          No findings available yet. Run analysis on a project or binary first.
        </div>
      ` : state.findings.map(f => renderFindingCard(f)).join("")}
    </div>
  `;
}

function renderFindingCard(f) {
  return `
    <div class="finding-card ${f.severity || 'info'}">
      <div class="finding-header">
        <div class="finding-title">${escapeHtml(f.title)}</div>
        <div style="display: flex; gap: 8px; align-items: center;">
          <span class="badge badge-${f.severity || 'info'}">${f.severity || 'info'}</span>
          <span class="badge badge-info">${f.module || 'engine'}</span>
        </div>
      </div>
      <div class="finding-meta">
        <span>File: ${escapeHtml(f.file || 'binary')}</span>
        ${f.line ? `<span> | Line: ${f.line}</span>` : ''}
        <span> | Rule: ${escapeHtml(f.rule || 'unknown')}</span>
        <span> | Confidence: ${f.confidence || 'medium'}</span>
      </div>
      <div class="finding-desc">${escapeHtml(f.description)}</div>
      ${f.evidence ? `
        <pre class="code-block" style="margin-top: 8px; margin-bottom: 8px;">${escapeHtml(typeof f.evidence === 'string' ? f.evidence : JSON.stringify(f.evidence, null, 2))}</pre>
      ` : ''}
      <div class="finding-remediation">
        <strong>💡 Remediation Guidance:</strong> ${escapeHtml(f.remediation || 'Inspect code and apply defense-in-depth controls.')}
      </div>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// 6. Reports View
// ---------------------------------------------------------------------------
function renderReports() {
  const currentReport = state.selectedAnalysis;

  return `
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">Structured Assessment Reports</div>
      <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">
        <select class="form-select" id="report-project-select" style="max-width: 300px;" onchange="loadProjectReport(this.value)">
          <option value="">-- Choose Project Report --</option>
          ${state.projects.map(p => `<option value="${p.id}" ${currentReport?.project_id === p.id ? 'selected' : ''}>${escapeHtml(p.name)}</option>`).join("")}
        </select>
        ${currentReport ? `
          <button class="btn btn-secondary" onclick="exportJsonReport()">📥 Export JSON</button>
          <button class="btn btn-primary" onclick="exportMarkdownReport()">📄 Export Markdown</button>
        ` : ''}
      </div>
    </div>

    ${currentReport ? `
      <div class="card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
          <div>
            <h2 style="font-size: 18px; font-weight: 700; color: #fff;">${escapeHtml(currentReport.project?.name || "Target Assessment")}</h2>
            <div style="color: var(--text-muted); font-size: 12px; font-family: var(--font-mono); margin-top: 4px;">
              Generated: ${new Date(currentReport.generated_at).toLocaleString()} | Scope: ${escapeHtml(currentReport.scope || "Authorized local inspection")}
            </div>
          </div>
          <span class="badge badge-low">STATUS: ${escapeHtml(currentReport.status || "COMPLETED")}</span>
        </div>

        <div style="background-color: rgba(6, 182, 212, 0.06); border: 1px solid rgba(6, 182, 212, 0.2); border-radius: 6px; padding: 14px; margin-bottom: 16px;">
          <strong style="color: var(--accent-cyan);">Executive Summary:</strong>
          <p style="margin-top: 6px; color: var(--text-primary); font-size: 13px;">
            ${escapeHtml(currentReport.executive_summary || "Analysis completed without critical findings.")}
          </p>
        </div>

        <div style="margin-bottom: 16px;">
          <div class="card-title">Tools & Engines Employed</div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-top: 6px;">
            ${(currentReport.tools_used || []).map(t => `<span class="badge badge-info">🛠️ ${escapeHtml(t)}</span>`).join("")}
          </div>
        </div>

        ${currentReport.limitations && currentReport.limitations.length > 0 ? `
          <div style="background-color: rgba(234, 179, 8, 0.08); border: 1px solid rgba(234, 179, 8, 0.25); border-radius: 6px; padding: 12px; margin-bottom: 16px;">
            <strong style="color: var(--sev-medium);">⚠️ Environmental Limitations Notice:</strong>
            <ul style="padding-left: 20px; margin-top: 6px; font-size: 12px; color: var(--text-secondary);">
              ${currentReport.limitations.map(l => `<li>${escapeHtml(l)}</li>`).join("")}
            </ul>
          </div>
        ` : ''}

        <div class="card-title">Identified Findings (${currentReport.findings?.length || 0})</div>
        <div style="margin-top: 10px;">
          ${(currentReport.findings || []).map(f => renderFindingCard(f)).join("")}
        </div>
      </div>
    ` : `
      <div class="card" style="text-align: center; padding: 48px; color: var(--text-muted);">
        Select a project from the dropdown above to view or export its structured report.
      </div>
    `}
  `;
}

// ---------------------------------------------------------------------------
// 7. Settings & Audit View
// ---------------------------------------------------------------------------
function renderSettings() {
  const caps = state.capabilities;

  return `
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">System Capabilities Matrix</div>
      <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">
        Live detection of reverse engineering and security tooling binaries installed in this Android / Termux / Debian environment.
      </p>

      <div class="table-container" style="margin-bottom: 0;">
        <table>
          <thead>
            <tr>
              <th>Tool Name</th>
              <th>Category</th>
              <th>Status</th>
              <th>Notes / Fallback</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style="font-weight: 600; color: #fff;">Python Runtime</td>
              <td>Core Engine</td>
              <td><span class="badge badge-low">ONLINE</span></td>
              <td>Native Python 3.13 parsers for ELF/PE/Mach-O headers</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">strings</td>
              <td>Binary Analysis</td>
              <td><span class="badge ${caps.strings ? 'badge-low' : 'badge-info'}">${caps.strings ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Supported with pure-Python regex fallback</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">objdump</td>
              <td>Disassembly</td>
              <td><span class="badge ${caps.objdump ? 'badge-low' : 'badge-info'}">${caps.objdump ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Binary disassembly integration</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">readelf</td>
              <td>ELF Inspection</td>
              <td><span class="badge ${caps.readelf ? 'badge-low' : 'badge-info'}">${caps.readelf ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Binutils header parsing</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">file</td>
              <td>Magic Detection</td>
              <td><span class="badge ${caps.file ? 'badge-low' : 'badge-info'}">${caps.file ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>File format classifier</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">nm</td>
              <td>Symbol Table</td>
              <td><span class="badge ${caps.nm ? 'badge-low' : 'badge-info'}">${caps.nm ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Object symbol extractor</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">yara</td>
              <td>Rule Matching</td>
              <td><span class="badge ${caps.yara ? 'badge-low' : 'badge-info'}">${caps.yara ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Optional signature engine</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">ghidra</td>
              <td>Decompiler</td>
              <td><span class="badge ${caps.ghidra ? 'badge-low' : 'badge-info'}">${caps.ghidra ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Advanced decompilation suite</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">radare2 / r2</td>
              <td>Framework</td>
              <td><span class="badge ${caps.radare2 ? 'badge-low' : 'badge-info'}">${caps.radare2 ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Low-level debugger/disassembler</td>
            </tr>
            <tr>
              <td style="font-weight: 600; color: #fff;">semgrep</td>
              <td>Static Analysis</td>
              <td><span class="badge ${caps.semgrep ? 'badge-low' : 'badge-info'}">${caps.semgrep ? 'AVAILABLE' : 'OFFLINE'}</span></td>
              <td>Multi-language AST pattern matcher</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Execution Audit Trail -->
    <div class="card">
      <div class="card-title">Execution Audit Trail (${state.auditLogs.length})</div>
      <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 12px;">
        Immutable audit log of all security tool invocations, scope validations, and execution outcomes.
      </p>

      ${state.auditLogs.length > 0 ? `
        <div class="table-container" style="margin-bottom: 0;">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Analysis ID</th>
                <th>Project ID</th>
                <th>Tools Used</th>
                <th>Findings</th>
                <th>Scope Status</th>
              </tr>
            </thead>
            <tbody>
              ${state.auditLogs.map(log => `
                <tr>
                  <td style="font-family: var(--font-mono); font-size: 11px;">${new Date(log.timestamp).toLocaleString()}</td>
                  <td style="font-family: var(--font-mono);">${escapeHtml(log.analysis_id || "N/A")}</td>
                  <td style="font-family: var(--font-mono);">${escapeHtml(log.project_id || "N/A")}</td>
                  <td>${(log.tools_used || []).join(", ")}</td>
                  <td><span class="badge badge-info">${log.finding_count || 0}</span></td>
                  <td><span class="badge badge-low">${escapeHtml(log.scope || "Authorized")}</span></td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : '<div style="color: var(--text-muted); padding: 12px;">No executions logged yet.</div>'}
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Event Handlers & API Coordination
// ---------------------------------------------------------------------------

function attachEventListeners() {
  // Navigation tabs
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", () => {
      const tab = item.getAttribute("data-tab");
      switchTab(tab);
    });
  });

  // Refresh button
  const refreshBtn = document.getElementById("btn-refresh");
  if (refreshBtn) refreshBtn.addEventListener("click", refreshData);

  // New Project Buttons
  const createModalBtn = document.getElementById("btn-modal-create-project");
  if (createModalBtn) createModalBtn.addEventListener("click", openCreateProjectModal);
  const emptyCreateBtn = document.getElementById("btn-empty-create-project");
  if (emptyCreateBtn) emptyCreateBtn.addEventListener("click", openCreateProjectModal);
  const quickNewBtn = document.getElementById("btn-quick-new-project");
  if (quickNewBtn) quickNewBtn.addEventListener("click", openCreateProjectModal);
}

window.switchTab = function(tab) {
  state.activeTab = tab;
  renderApp();
};

window.switchSubtab = function(tabId) {
  document.querySelectorAll(".subtab-content").forEach(el => el.style.display = "none");
  document.querySelectorAll("#re-subtabs .tab-btn").forEach(el => el.classList.remove("active"));
  const target = document.getElementById(tabId);
  if (target) target.style.display = "block";
  event.target.classList.add("active");
};

// Modal: Create Project
function openCreateProjectModal() {
  const container = document.getElementById("modal-container");
  container.innerHTML = `
    <div class="modal-backdrop" onclick="closeModal(event)">
      <div class="modal" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3 style="font-size: 16px; font-weight: 700;">Create Target Project</h3>
          <button style="background: none; border: none; color: var(--text-muted); font-size: 18px; cursor: pointer;" onclick="closeModal()">✕</button>
        </div>
        <form id="create-project-form" onsubmit="handleCreateProject(event)">
          <div class="modal-body">
            <div class="form-group">
              <label class="form-label">Project Name</label>
              <input type="text" class="form-input" id="new-project-name" placeholder="e.g. Lab Binary Assessment" required maxlength="80">
            </div>
            <div class="form-group">
              <label class="form-label">Description (Optional)</label>
              <textarea class="form-textarea" id="new-project-desc" rows="3" placeholder="Target scope and notes..."></textarea>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" onclick="closeModal()">Cancel</button>
            <button type="submit" class="btn btn-primary">Create Project</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

window.closeModal = function() {
  document.getElementById("modal-container").innerHTML = "";
};

async function handleCreateProject(e) {
  e.preventDefault();
  const name = document.getElementById("new-project-name").value;
  const description = document.getElementById("new-project-desc").value;

  try {
    const proj = await api.createProject(name, description);
    state.projects.unshift(proj);
    closeModal();
    renderApp();
  } catch (err) {
    alert(`Failed creating project: ${err.message}`);
  }
}

window.handleArchiveUpload = async function(projectId, file) {
  if (!file) return;
  try {
    await api.uploadArchive(projectId, file);
    alert(`Archive "${file.name}" successfully extracted with traversal protection!`);
    await refreshData();
  } catch (err) {
    alert(`Archive upload failed: ${err.message}`);
  }
};

window.handleRunAnalysis = async function(projectId) {
  try {
    const report = await api.analyzeProject(projectId);
    state.selectedAnalysis = report;
    state.findings = report.findings || [];
    alert(`Analysis complete! Identified ${report.findings?.length || 0} findings.`);
    await refreshData();
    switchTab("reports");
  } catch (err) {
    alert(`Analysis failed: ${err.message}`);
  }
};

window.handleDeleteProject = async function(projectId) {
  if (!confirm("Are you sure you want to delete this project?")) return;
  try {
    await api.deleteProject(projectId);
    state.projects = state.projects.filter(p => p.id !== projectId);
    renderApp();
  } catch (err) {
    alert(`Failed deleting project: ${err.message}`);
  }
};

window.handleDirectREUpload = async function(file) {
  if (!file) return;
  try {
    const result = await api.analyzeBinaryDirect(file);
    state.reResult = result;
    if (result.findings) {
      state.findings = [...result.findings, ...state.findings];
    }
    renderApp();
  } catch (err) {
    alert(`Reverse engineering failed: ${err.message}`);
  }
};

window.handleProjectRESelect = async function(projectId) {
  if (!projectId) return;
  try {
    const report = await api.getProjectReport(projectId);
    if (report && report.reverse_engineering) {
      state.reResult = {
        tool_used: "wizard-re-engine",
        input_file: report.project?.name || "Project",
        status: report.reverse_engineering.status || "completed",
        metadata: report.reverse_engineering.metadata,
        strings: report.reverse_engineering.strings,
        findings: report.reverse_engineering.findings || [],
        disassembly: [],
      };
      renderApp();
    }
  } catch (err) {
    alert(`Failed retrieving project binary info: ${err.message}`);
  }
};

window.handleSecurityFormSubmit = async function(e) {
  e.preventDefault();
  const projectId = document.getElementById("sec-project-id").value;
  const target = document.getElementById("sec-target").value;
  const mode = document.getElementById("sec-mode").value;
  const authorized = document.getElementById("sec-authorized").checked;

  try {
    const res = await api.analyzeSecurity({
      project_id: projectId,
      scope: {
        target,
        authorized,
        allowed_hosts: ["127.0.0.1", "localhost"],
        allowed_ports: [80, 443, 8000, 8080, 5173],
        mode,
      },
    });
    state.secResult = res;
    if (res.findings) {
      state.findings = [...res.findings, ...state.findings];
    }
    alert(`Security testing completed. Found ${res.finding_count || 0} issues.`);
    renderApp();
  } catch (err) {
    alert(`Security testing rejected: ${err.message}`);
  }
};

window.viewProjectReport = function(projectId) {
  loadProjectReport(projectId);
  switchTab("reports");
};

window.loadProjectReport = async function(projectId) {
  if (!projectId) return;
  try {
    const rep = await api.getProjectReport(projectId);
    state.selectedAnalysis = rep;
    renderApp();
  } catch (err) {
    alert(`No report found for this project: ${err.message}`);
  }
};

window.filterFindings = function(severity) {
  if (severity === "all") {
    renderApp();
    return;
  }
  const filtered = state.findings.filter(f => f.severity === severity);
  const container = document.getElementById("findings-list-container");
  if (container) {
    container.innerHTML = filtered.length > 0 ? filtered.map(f => renderFindingCard(f)).join("") : `
      <div class="card" style="text-align: center; padding: 24px; color: var(--text-muted);">
        No findings with severity "${severity}".
      </div>
    `;
  }
};

window.handleFindingsSearch = function(query) {
  const q = query.toLowerCase();
  const filtered = state.findings.filter(f => 
    (f.title && f.title.toLowerCase().includes(q)) ||
    (f.description && f.description.toLowerCase().includes(q)) ||
    (f.rule && f.rule.toLowerCase().includes(q)) ||
    (f.file && f.file.toLowerCase().includes(q))
  );
  const container = document.getElementById("findings-list-container");
  if (container) {
    container.innerHTML = filtered.length > 0 ? filtered.map(f => renderFindingCard(f)).join("") : `
      <div class="card" style="text-align: center; padding: 24px; color: var(--text-muted);">
        No findings matching "${escapeHtml(query)}".
      </div>
    `;
  }
};

window.exportJsonReport = function() {
  if (!state.selectedAnalysis) return;
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.selectedAnalysis, null, 2));
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `wizard_report_${state.selectedAnalysis.project_id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
};

window.exportMarkdownReport = function() {
  if (!state.selectedAnalysis) return;
  const rep = state.selectedAnalysis;
  let md = `# WIZARD CYBERSECURITY ASSESSMENT REPORT\n\n`;
  md += `**Target Project:** ${rep.project?.name || "N/A"}\n`;
  md += `**Generated At:** ${rep.generated_at}\n`;
  md += `**Scope:** ${rep.scope}\n`;
  md += `**Tools Used:** ${(rep.tools_used || []).join(", ")}\n\n`;
  md += `## Executive Summary\n\n${rep.executive_summary}\n\n`;
  md += `## Findings Summary\n\n`;
  md += `- Critical: ${rep.severity_counts?.critical || 0}\n`;
  md += `- High: ${rep.severity_counts?.high || 0}\n`;
  md += `- Medium: ${rep.severity_counts?.medium || 0}\n`;
  md += `- Low: ${rep.severity_counts?.low || 0}\n`;
  md += `- Info: ${rep.severity_counts?.info || 0}\n\n`;
  md += `## Findings Details\n\n`;
  (rep.findings || []).forEach((f, i) => {
    md += `### ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **Rule ID:** \`${f.rule}\`\n`;
    md += `- **File:** \`${f.file}\`${f.line ? ` (Line ${f.line})` : ""}\n`;
    md += `- **Confidence:** ${f.confidence}\n\n`;
    md += `**Description:**\n${f.description}\n\n`;
    if (f.evidence) {
      md += `**Evidence:**\n\`\`\`\n${typeof f.evidence === "string" ? f.evidence : JSON.stringify(f.evidence, null, 2)}\n\`\`\`\n\n`;
    }
    md += `**Remediation Guidance:**\n${f.remediation}\n\n---\n\n`;
  });

  const dataStr = "data:text/markdown;charset=utf-8," + encodeURIComponent(md);
  const downloadAnchor = document.createElement("a");
  downloadAnchor.setAttribute("href", dataStr);
  downloadAnchor.setAttribute("download", `wizard_report_${rep.project_id}.md`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
};

// Utilities
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatBytes(bytes, decimals = 2) {
  if (!bytes) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

async function refreshData() {
  try {
    const [caps, projs, analyses, audit] = await Promise.all([
      api.getCapabilities().catch(() => ({})),
      api.getProjects().catch(() => []),
      api.getAnalyses().catch(() => []),
      api.getAuditLogs().catch(() => []),
    ]);
    state.capabilities = caps;
    state.projects = projs;
    state.analyses = analyses;
    state.auditLogs = audit;
    renderApp();
  } catch (err) {
    console.error("Refresh error:", err);
  }
}

// Initial Boot
async function init() {
  await refreshData();
}

init();
