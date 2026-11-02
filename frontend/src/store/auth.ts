import { create } from "zustand";
import { authApi, type UserResponse } from "../api/client";

interface BootstrapInfo {
  username: string;
  password: string | null;
  source: string;
}

interface AuthState {
  user: UserResponse | null;
  token: string | null;
  refreshToken: string | null;
  isLoading: boolean;
  needsSetup: boolean;
  bootstrap: BootstrapInfo | null;
  initialized: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
  checkStatus: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: sessionStorage.getItem("fstec_token"),
  refreshToken: sessionStorage.getItem("fstec_refresh"),
  isLoading: false,
  needsSetup: false,
  bootstrap: null,
  initialized: false,

  login: async (username, password) => {
    const { data } = await authApi.login(username, password);
    sessionStorage.setItem("fstec_token", data.access_token);
    if (data.refresh_token) sessionStorage.setItem("fstec_refresh", data.refresh_token);
    const { data: user } = await authApi.me();
    set({ token: data.access_token, refreshToken: data.refresh_token || null, user, needsSetup: false, bootstrap: null, initialized: true });
  },

  logout: () => {
    const refresh = sessionStorage.getItem("fstec_refresh") || undefined;
    const access = sessionStorage.getItem("fstec_token") || undefined;
    void authApi.logout(refresh, access).finally(() => {
      sessionStorage.removeItem("fstec_token");
      sessionStorage.removeItem("fstec_refresh");
      sessionStorage.removeItem("fstec_user");
    });
    sessionStorage.removeItem("fstec_token");
    sessionStorage.removeItem("fstec_refresh");
    sessionStorage.removeItem("fstec_user");
    set({ user: null, token: null, refreshToken: null, initialized: true, bootstrap: null });
  },

  checkAuth: async () => {
    const token = sessionStorage.getItem("fstec_token");
    if (!token) {
      set({ user: null, token: null, initialized: true });
      return;
    }
    try {
      const { data } = await authApi.me();
      set({ user: data, token, initialized: true });
    } catch {
      sessionStorage.removeItem("fstec_token");
      sessionStorage.removeItem("fstec_refresh");
      sessionStorage.removeItem("fstec_user");
      set({ user: null, token: null, refreshToken: null, initialized: true });
    }
  },

  checkStatus: async () => {
    for (let i = 0; i < 30; i++) {
      try {
        const { data } = await authApi.status();
        set({
          needsSetup: data.needs_setup,
          bootstrap: data.needs_setup
            ? {
                username: data.bootstrap_username || "admin",
                password: data.bootstrap_password ?? null,
                source: data.bootstrap_source || "file",
              }
            : null,
          initialized: true,
        });
        return;
      } catch {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
    set({ needsSetup: false, bootstrap: null, initialized: true });
  },
}));
