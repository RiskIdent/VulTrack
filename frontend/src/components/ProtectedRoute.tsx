import { type ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

interface ProtectedRouteProps {
  children: ReactNode;
}

/**
 * When auth is enabled, redirects to /login if the user is not authenticated.
 * When auth is disabled or user is logged in, renders children.
 */
export default function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { user, loading, authEnabled } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0f0d] flex items-center justify-center">
        <div className="text-[#a5d6a7]">Loading...</div>
      </div>
    );
  }

  if (authEnabled && !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
}
