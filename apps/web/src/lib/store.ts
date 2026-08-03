"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { AnalysisReport, Project } from "./types";

interface BinarisState {
  token: string | null;
  email: string | null;
  orgId: string | null;
  projects: Project[];
  activeProjectId: string | null;
  report: AnalysisReport | null;
  selectedFunctionId: string | null;
  chatSessionId: string | null;
  setAuth: (token: string, email: string, orgId: string) => void;
  logout: () => void;
  setProjects: (projects: Project[]) => void;
  setActiveProject: (id: string) => void;
  setReport: (report: AnalysisReport | null) => void;
  setSelectedFunction: (id: string | null) => void;
  setChatSession: (id: string | null) => void;
}

export const useBinarisStore = create<BinarisState>()(
  persist(
    (set) => ({
      token: null,
      email: null,
      orgId: null,
      projects: [],
      activeProjectId: null,
      report: null,
      selectedFunctionId: null,
      chatSessionId: null,
      setAuth: (token, email, orgId) => set({ token, email, orgId }),
      logout: () =>
        set({
          token: null,
          email: null,
          orgId: null,
          projects: [],
          activeProjectId: null,
          report: null,
          chatSessionId: null,
        }),
      setProjects: (projects) =>
        set({
          projects,
          activeProjectId: projects[0]?.id ?? null,
        }),
      setActiveProject: (id) => set({ activeProjectId: id }),
      setReport: (report) => set({ report, selectedFunctionId: report?.functions[0]?.id ?? null }),
      setSelectedFunction: (id) => set({ selectedFunctionId: id }),
      setChatSession: (id) => set({ chatSessionId: id }),
    }),
    {
      name: "binaris-session",
      partialize: (s) => ({
        token: s.token,
        email: s.email,
        orgId: s.orgId,
        activeProjectId: s.activeProjectId,
      }),
    },
  ),
);
