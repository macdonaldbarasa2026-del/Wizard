// Wizard API Service Client
const API_BASE = window.location.origin;

export async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, options);

  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || JSON.stringify(errJson);
    } catch (_) {}
    throw new Error(errorDetail || `Request failed with status ${response.status}`);
  }

  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

export const api = {
  // Capabilities
  getCapabilities: () => request("/api/capabilities"),

  // Modules & Health
  getHealth: () => request("/health"),
  getModules: () => request("/api/modules"),

  // Projects
  getProjects: () => request("/api/projects"),
  getProject: (id) => request(`/api/projects/${id}`),
  createProject: (name, description) =>
    request("/api/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description }),
    }),
  deleteProject: (id) =>
    request(`/api/projects/${id}`, {
      method: "DELETE",
    }),
  uploadArchive: (projectId, file) => {
    const formData = new FormData();
    formData.append("archive", file);
    return request(`/api/projects/${projectId}/upload`, {
      method: "POST",
      body: formData,
    });
  },
  analyzeProject: (projectId, payload = {}) =>
    request(`/api/projects/${projectId}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getProjectReport: (projectId) => request(`/api/projects/${projectId}/report`),

  // Reverse Engineering
  analyzeBinaryDirect: (file) => {
    const formData = new FormData();
    formData.append("file", file);
    return request("/api/reverse-engineering/analyze", {
      method: "POST",
      body: formData,
    });
  },

  // Security Testing
  analyzeSecurity: (payload) =>
    request("/api/security-testing/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),

  // Analyses
  getAnalyses: () => request("/api/analyses"),
  getAnalysis: (id) => request(`/api/analyses/${id}`),
  getAnalysisFindings: (id, severity = "", module = "") => {
    const params = new URLSearchParams();
    if (severity) params.append("severity", severity);
    if (module) params.append("module", module);
    const qs = params.toString() ? `?${params.toString()}` : "";
    return request(`/api/analyses/${id}/findings${qs}`);
  },

  // Audit Logs
  getAuditLogs: (limit = 50) => request(`/api/audit?limit=${limit}`),
};
