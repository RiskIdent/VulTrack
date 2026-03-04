import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { getAuthMe, getLoginURL, logout as apiLogout } from '../api/client';

export interface User {
  id: number;
  email: string;
  name: string;
  isAdmin: boolean;
}

interface AuthState {
  user: User | null;
  loading: boolean;
  authEnabled: boolean;
}

interface AuthContextValue extends AuthState {
  login: () => void;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [authEnabled, setAuthEnabled] = useState(false);

  const refreshUser = useCallback(async () => {
    try {
      const data = await getAuthMe();
      if ('authEnabled' in data && data.authEnabled === false) {
        setAuthEnabled(false);
        setUser(null);
        return;
      }
      if (typeof data.id === 'number' && typeof data.email === 'string') {
        setAuthEnabled(true);
        setUser({
          id: data.id,
          email: data.email,
          name: data.name ?? '',
          isAdmin: data.isAdmin ?? false,
        });
      } else {
        setAuthEnabled(true);
        setUser(null);
      }
    } catch {
      setAuthEnabled(true);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = useCallback(() => {
    window.location.href = getLoginURL();
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
    // Backend may redirect; if not, we've cleared local state
    window.location.href = '/';
  }, []);

  const value: AuthContextValue = {
    user,
    loading,
    authEnabled,
    login,
    logout,
    refreshUser,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return ctx;
}
