import axios from "axios";

const API_BASE = (import.meta.env.VITE_API_BASE ?? "/gw").replace(/\/$/, "");

export const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem("fstec_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    const hadAuth = Boolean(original?.headers?.Authorization);
    if (error.response?.status === 401 && hadAuth && original && !original._retry
        && !String(original.url || "").includes("/api/auth/login")
        && !String(original.url || "").includes("/api/auth/refresh")) {
      const refresh = sessionStorage.getItem("fstec_refresh");
      if (refresh) {
        original._retry = true;
        try {
          const r = await axios.post(`${API_BASE}/api/auth/refresh`, { refresh_token: refresh });
          sessionStorage.setItem("fstec_token", r.data.access_token);
          if (r.data.refresh_token) sessionStorage.setItem("fstec_refresh", r.data.refresh_token);
          original.headers = original.headers || {};
          original.headers.Authorization = `Bearer ${r.data.access_token}`;
          return api(original);
        } catch {
          // fall through to logout
        }
      }
    }
    if (error.response?.status === 401 && hadAuth) {
      sessionStorage.removeItem("fstec_token");
      sessionStorage.removeItem("fstec_refresh");
      sessionStorage.removeItem("fstec_user");
      if (window.location.pathname !== "/login") {
        window.location.href = `${import.meta.env.BASE_URL}login`;
      }
    } else if (error.response?.status === 403) {
      window.dispatchEvent(new CustomEvent("fstec-api-error", {
        detail: error.response?.data?.detail || "Недостаточно прав",
      }));
    } else if (error.response?.status >= 500 || !error.response) {
      window.dispatchEvent(new CustomEvent("fstec-api-error", {
        detail: error.response?.data?.detail || "Ошибка сервера",
      }));
    }
    return Promise.reject(error);
  }
);

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  role: string;
  username: string;
}

export interface UserResponse {
  id: number;
  username: string;
  full_name: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

export interface StatsResponse {
  total_letters: number;
  hacker_letters: number;
  compromise_letters?: number;
  vulnerability_letters: number;
  other_letters: number;
  total_threats: number;
  total_iocs: number;
  total_vulns: number;
}

export interface LetterListItem {
  id: number;
  letter_number: string;
  letter_date: string;
  letter_type: string;
  status: string;
  created_at: string;
  threat_count: number;
  ioc_count: number;
  vuln_count: number;
}

export interface AttachmentResponse {
  id: number;
  filename: string;
  file_type: string;
  parse_status: string;
  parse_errors: string;
  parsed_text: string;
}

export interface ThreatResponse {
  id: number;
  number: number;
  group_name: string;
  threat_type: string;
  theme: string;
  archive_name: string;
  exe_name: string;
  malware_type: string;
  description: string;
  measures: string;
}

export interface IoCResponse {
  id: number;
  ioc_type: string;
  value: string;
  context: string;
}

export interface VulnerabilityResponse {
  id: number;
  bdu_id: string;
  cve_id: string;
  description: string;
  software: string;
  severity: string;
  cvss_score?: number | null;
  cpe?: string;
  affected_range?: string;
  fixed_version?: string;
  patch_url?: string;
  source?: string;
  cmdb_match?: boolean;
  cmdb_error?: string;
  current_version?: string;
  target_version?: string;
  recommendation?: string;
  is_applicable: boolean | null;
  applicability_notes: string;
  action_type: string;
  action_details: string;
  response_point: string;
}

export interface VulnerabilityAutofillResult {
  action_type: string;
  applicability: "true" | "false" | "unknown";
  current_version?: string;
  action_details: string;
  applicability_notes: string;
  source?: string;
  model?: string;
  llm_used?: boolean;
}

export interface VulnerabilityUpdateData {
  bdu_id?: string;
  cve_id?: string;
  description?: string;
  severity?: string;
  cvss_score?: number | null;
  is_applicable?: boolean | null;
  applicability_notes?: string;
  action_type?: string;
  action_details?: string;
  response_point?: string;
  software?: string;
  current_version?: string;
  target_version?: string;
  fixed_version?: string;
}

export interface SummaryResponse {
  id: number;
  summary: string;
  confidence: number;
}

export interface EntityResponse {
  id: number;
  entity_type: string;
  value: string;
  context?: string;
}

export interface LetterResponse {
  id: number;
  letter_number: string;
  letter_date: string;
  letter_type: string;
  status: string;
  sla: string;
  routing: string;
  source_filename: string;
  processing_stage: string;
  subject: string;
  original_text: string;
  all_text: string;
  parse_errors: string;
  created_at: string;
  updated_at: string;
  attachments: AttachmentResponse[];
  tables?: Array<{ index: number; rows: string[][] }>;
  progress_percent?: number;
  eta_seconds?: number | null;
  threats: ThreatResponse[];
  iocs: IoCResponse[];
  vulnerabilities: VulnerabilityResponse[];
  entities?: EntityResponse[];
  summaries?: SummaryResponse[];
  response?: { text: string; exists: boolean; id?: number };
  report?: { filename?: string; generated_at?: string };
}

export const authApi = {
  login: (username: string, password: string) =>
    api.post<TokenResponse>("/api/auth/login", { username, password }),
  me: () => api.get<UserResponse>("/api/auth/me"),
  refresh: (refreshToken: string) =>
    api.post<TokenResponse>("/api/auth/refresh", { refresh_token: refreshToken }),
  logout: (refreshToken?: string, accessToken?: string) =>
    axios.post<{ ok: boolean }>(`${API_BASE}/api/auth/logout`,
      refreshToken ? { refresh_token: refreshToken } : {},
      accessToken ? { headers: { Authorization: `Bearer ${accessToken}` } } : {}),
  status: () =>
    api.get<{
      needs_setup: boolean;
      bootstrap_username?: string;
      bootstrap_password?: string | null;
      bootstrap_source?: string;
    }>("/api/auth/status"),
};

export const lettersApi = {
  list: (params?: { letter_type?: string; status?: string; skip?: number; limit?: number; mine?: boolean }) =>
    api.get<LetterListItem[]>("/api/letters", { params }),
  stats: (params?: { mine?: boolean }) => api.get<StatsResponse>("/api/letters/stats", { params }),
  get: (id: number, view = false) =>
    api.get<LetterResponse>(`/api/letters/${id}`, { params: view ? { view: 1 } : {} }),
  delete: (id: number) => api.delete(`/api/letters/${id}`),
  upload: (files: File[]) => {
    const formData = new FormData();
    files.forEach((f) => formData.append("files", f));
    return api.post<{ id: number; status: string; filename: string; duplicate?: boolean }>("/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
  generate: (id: number) => api.post<{ id: number; document_id: number; status: string; text: string }>(
    `/reply/generate`, undefined, { params: { doc_id: id } }
  ),
  getResponseText: (id: number) =>
    api.get<{ text: string; exists: boolean }>(`/api/letters/${id}/response/text`),
  getResponsePreview: (id: number) =>
    api.get<{
      title: string;
      intro: string;
      text?: string;
      response_exists?: boolean;
      sections: Array<{
        threat_id: number;
        number: number;
        prefix: string;
        description: string;
        measures: string[];
        measures_preview: string[];
        measure_annotations?: Array<{
          text: string;
          source: string;
          candidate_id?: number | null;
        }>;
        threat_type: string;
        measure_options: string[];
        base_measures: string[];
        intro_text: string;
        section_text: string;
      }>;
    }>(`/api/letters/${id}/response/preview`),
  updateThreatMeasures: (letterId: number, threatId: number, measures: string[]) =>
    api.put<{ measures: string[] }>(`/api/letters/${letterId}/response/measures/${threatId}`, { measures }),
  download: (id: number) =>
    api.get(`/api/letters/${id}/download`, { responseType: "blob" }),
  updateResponse: (id: number, content: string) =>
    api.put(`/api/letters/${id}/response`, { content }),
  exportIocs: (id: number, type: string) =>
    api.get(`/api/letters/${id}/export/${type}`, { responseType: "blob" }),
  exportIocsDocx: (id: number, type: string) =>
    api.get(`/api/letters/${id}/export/${type}/docx`, { responseType: "blob" }),
  createIoc: (letterId: number, data: { value: string; ioc_type: string }) =>
    api.post<LetterResponse>(`/api/letters/${letterId}/iocs`, data),
  updateIoc: (letterId: number, iocId: number, data: { value?: string; ioc_type?: string }) =>
    api.put<LetterResponse>(`/api/letters/${letterId}/iocs/${iocId}`, data),
  deleteIoc: (letterId: number, iocId: number) =>
    api.delete<LetterResponse>(`/api/letters/${letterId}/iocs/${iocId}`),
  updateVulnerability: (letterId: number, vulnId: number, data: VulnerabilityUpdateData) =>
    api.put<LetterResponse>(`/api/letters/${letterId}/vulnerabilities/${vulnId}`, data),
  autofillVulnerability: (letterId: number, vulnId: number) =>
    api.post<VulnerabilityAutofillResult>(`/api/letters/${letterId}/vulnerabilities/${vulnId}/autofill`),
};

// ТЗ 2.6: нижнеуровневые эндпоинты gateway
export const documentsApi = {
  list: (params?: { letter_type?: string; status?: string; skip?: number; limit?: number }) =>
    api.get<DocumentListItem[]>("/documents", { params }),
  get: (id: number) => api.get<LetterResponse>(`/documents/${id}`),
  downloadReport: (id: number) =>
    api.get(`/reports/${id}/download`, { responseType: "blob" }),
  regenerateReport: (id: number) =>
    api.post<{ filename: string; document_id: number }>(`/reports/${id}/regenerate`),
  downloadRaw: (id: number) =>
    api.get(`/reports/${id}/download_raw`, { responseType: "blob" }),
  generateReply: (id: number) =>
    api.post<{ id: number; document_id: number; status: string; text: string }>(
      `/reply/generate`, undefined, { params: { doc_id: id } }
    ),
};

export interface DocumentListItem {
  id: number;
  letter_number: string;
  letter_date: string;
  letter_type: string;
  status: string;
  sla: string;
  routing: string;
  source_filename: string;
  processing_stage: string;
  created_at: string;
}

export interface AuditItem {
  id: number;
  user_id?: number | null;
  username: string;
  action: string;
  object_type: string;
  object_id?: number | null;
  filename: string;
  document_id?: number | null;
  ip_address: string;
  created_at: string;
}

export const auditApi = {
  list: (params?: { skip?: number; limit?: number; action?: string; document_id?: number }) =>
    api.get<{ total: number; items: AuditItem[] }>("/api/audit", { params }),
};

export const usersApi = {
  list: () => api.get<UserResponse[]>("/api/users"),
  create: (data: { username: string; password: string; role: string; full_name: string }) =>
    api.post<UserResponse>("/api/users", data),
  update: (id: number, data: Partial<{ full_name: string; password: string; role: string; is_active: boolean }>) =>
    api.put<UserResponse>(`/api/users/${id}`, data),
  delete: (id: number) =>
    api.delete<{ id: number; deleted: boolean; deactivated: boolean; detail?: string }>(`/api/users/${id}`),
};

export interface ThreatTypeResponse {
  id: number;
  name: string;
  key: string;
  description: string;
  created_at: string;
}

export interface MeasureTemplateResponse {
  id: number;
  name: string;
  threat_type_id: number | null;
  measures: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export interface VulnMeasureTemplateResponse {
  id: number;
  name: string;
  vuln_type_id: number | null;
  action_type: string;
  content: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

export const templatesApi = {
  listThreatTypes: () => api.get<ThreatTypeResponse[]>("/api/templates/threat-types"),
  createThreatType: (data: { name: string; key: string; description: string }) =>
    api.post<ThreatTypeResponse>("/api/templates/threat-types", data),
  updateThreatType: (id: number, data: Partial<{ name: string; description: string }>) =>
    api.put<ThreatTypeResponse>(`/api/templates/threat-types/${id}`, data),
  deleteThreatType: (id: number) => api.delete(`/api/templates/threat-types/${id}`),

  listMeasureTemplates: (threatTypeId?: number) =>
    api.get<MeasureTemplateResponse[]>("/api/templates/measure-templates", { params: threatTypeId ? { threat_type_id: threatTypeId } : {} }),
  createMeasureTemplate: (data: { name: string; threat_type_id: number | null; measures: string; is_default: boolean }) =>
    api.post<MeasureTemplateResponse>("/api/templates/measure-templates", data),
  updateMeasureTemplate: (id: number, data: Partial<{ name: string; threat_type_id: number; measures: string; is_default: boolean }>) =>
    api.put<MeasureTemplateResponse>(`/api/templates/measure-templates/${id}`, data),
  deleteMeasureTemplate: (id: number) => api.delete(`/api/templates/measure-templates/${id}`),

  listVulnTemplates: () =>
    api.get<VulnMeasureTemplateResponse[]>("/api/templates/vuln-templates"),
  createVulnTemplate: (data: { name: string; action_type: string; content: string; is_default: boolean }) =>
    api.post<VulnMeasureTemplateResponse>("/api/templates/vuln-templates", data),
  updateVulnTemplate: (id: number, data: Partial<{ name: string; action_type: string; content: string; is_default: boolean }>) =>
    api.put<VulnMeasureTemplateResponse>(`/api/templates/vuln-templates/${id}`, data),
  deleteVulnTemplate: (id: number) => api.delete(`/api/templates/vuln-templates/${id}`),
};

export interface MeasureCandidate {
  id: number;
  text: string;
  note: string;
  status: string;
  document_id: number | null;
  threat_id?: number | null;
  letter_number: string;
  letter_date: string;
  threat_theme: string;
  created_at: string | null;
  reviewed_at: string | null;
}

export const candidatesApi = {
  list: (status: string = "pending") =>
    api.get<MeasureCandidate[]>("/admin/measures/candidates", { params: { status } }),
  accept: (id: number) =>
    api.post<{ id: number; status: string; measure_id?: number }>(`/admin/measures/candidates/${id}/accept`),
  reject: (id: number) =>
    api.post<{ id: number; status: string }>(`/admin/measures/candidates/${id}/reject`),
};

export interface ServiceHealth {
  name: string;
  pid: number | null;
  started: number | null;
  last_seen: number | null;
  alive: boolean;
  pid_exists: boolean;
  heartbeat_age_sec: number | null;
}

export interface ExternalProbe {
  name: string;
  url: string;
  reachable: boolean;
  http_status: number | null;
  latency_ms: number;
  error: string;
}

export interface DbHealth {
  name: string;
  reachable: boolean;
  latency_ms: number;
  error: string;
}

export interface LlmInfo {
  provider: string;
  base_url: string;
  model: string;
  reachable: boolean;
  http_status: number | null;
  latency_ms: number;
  error: string;
  note: string;
}

export interface DiagnosticsResponse {
  services: ServiceHealth[];
  external: ExternalProbe[];
  db: DbHealth;
  llm: LlmInfo;
  gateway: ExternalProbe;
  system: {
    cpu_percent: number;
    memory_mb: number;
    memory_total_mb: number;
    disk_free_gb: number;
    gateway_proc_cpu_percent: number;
    gateway_proc_memory_mb: number;
    gateway_uptime_sec: number;
  };
}

export const diagnosticsApi = {
  get: () => api.get<DiagnosticsResponse>("/api/diagnostics"),
  bus: () => api.get<{ backend?: string; total: number; topics: Array<{ topic: string; count: number; last_id: number }>; error?: string }>("/api/diagnostics/bus"),
};
