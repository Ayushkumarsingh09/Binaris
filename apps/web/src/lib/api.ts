import type { AnalysisReport, AuthResponse, ChatResponse, Project } from "./types";

const API_BASE = process.env.NEXT_PUBLIC_BINARIS_API_URL ?? "http://127.0.0.1:8080";

function authHeaders(token?: string | null): HeadersInit {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function parse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  return res.json() as Promise<T>;
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return parse(res);
}

export async function register(
  email: string,
  password: string,
  name: string,
): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/v1/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, name }),
  });
  return parse(res);
}

export async function listProjects(token: string): Promise<Project[]> {
  const res = await fetch(`${API_BASE}/v1/projects`, {
    headers: authHeaders(token),
  });
  return parse(res);
}

export async function uploadBinary(
  token: string,
  projectId: string,
  file: File,
): Promise<AnalysisReport> {
  const form = new FormData();
  form.append("file", file, file.name);
  const res = await fetch(`${API_BASE}/v1/projects/${projectId}/upload`, {
    method: "POST",
    headers: authHeaders(token),
    body: form,
  });
  return parse(res);
}

export async function getAnalysis(token: string, id: string): Promise<AnalysisReport> {
  const res = await fetch(`${API_BASE}/v1/analyses/${id}`, {
    headers: authHeaders(token),
  });
  return parse(res);
}

export async function chatWithBinary(
  token: string,
  analysisId: string,
  message: string,
  sessionId?: string,
): Promise<ChatResponse> {
  const res = await fetch(`${API_BASE}/v1/analyses/${analysisId}/chat`, {
    method: "POST",
    headers: {
      ...authHeaders(token),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ message, session_id: sessionId }),
  });
  return parse(res);
}

export async function searchAnalysis(
  token: string,
  analysisId: string,
  q: string,
  kind = "all",
): Promise<unknown> {
  const res = await fetch(
    `${API_BASE}/v1/analyses/${analysisId}/search?q=${encodeURIComponent(q)}&kind=${kind}`,
    { headers: authHeaders(token) },
  );
  return parse(res);
}

export async function listReports(token: string, analysisId: string): Promise<unknown> {
  const res = await fetch(`${API_BASE}/v1/analyses/${analysisId}/reports`, {
    headers: authHeaders(token),
  });
  return parse(res);
}

export async function listOAuthProviders(): Promise<{ providers: string[] }> {
  const res = await fetch(`${API_BASE}/v1/auth/oauth/providers`);
  return parse(res);
}

export function oauthStartUrl(provider: string): string {
  return `${API_BASE}/v1/auth/oauth/${provider}/start`;
}

export async function createSnapshot(
  token: string,
  analysisId: string,
  label?: string,
): Promise<{ id: string; label: string }> {
  const res = await fetch(`${API_BASE}/v1/analyses/${analysisId}/snapshots`, {
    method: "POST",
    headers: { ...authHeaders(token), "Content-Type": "application/json" },
    body: JSON.stringify({ label: label ?? "manual" }),
  });
  return parse(res);
}

export async function listSnapshots(
  token: string,
  analysisId: string,
): Promise<{ snapshots: { id: string; label: string; created_at: string; sha256: string }[] }> {
  const res = await fetch(`${API_BASE}/v1/analyses/${analysisId}/snapshots`, {
    headers: authHeaders(token),
  });
  return parse(res);
}

export async function restoreSnapshot(token: string, snapshotId: string): Promise<unknown> {
  const res = await fetch(`${API_BASE}/v1/snapshots/${snapshotId}/restore`, {
    method: "POST",
    headers: authHeaders(token),
  });
  return parse(res);
}

export async function diffAnalyses(
  token: string,
  leftId: string,
  rightId: string,
): Promise<unknown> {
  const res = await fetch(`${API_BASE}/v1/analyses/${leftId}/diff/${rightId}`, {
    headers: authHeaders(token),
  });
  return parse(res);
}

export { API_BASE };
