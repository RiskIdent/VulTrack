import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Servers from './pages/Servers';
import ServerDetail from './pages/ServerDetail';
import Findings from './pages/Findings';
import Triage from './pages/Triage';
import TriageDetail from './pages/TriageDetail';
import Assessments from './pages/Assessments';
import Statistics from './pages/Statistics';
import Reports from './pages/Reports';
import Admin from './pages/Admin';
import OVALDatabase from './pages/OVALDatabase';
import Scans from './pages/Scans';
import ServerGroupMembers from './pages/ServerGroupMembers';

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, authEnabled } = useAuth();
  // When auth is disabled, allow access (no roles enforced)
  if (!authEnabled) return <>{children}</>;
  // When auth is enabled, only admins may enter
  if (!user?.isAdmin) return <Navigate to="/" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="servers" element={<Servers />} />
          <Route path="servers/:id" element={<ServerDetail />} />
          <Route path="scans" element={<Scans />} />
          <Route path="findings" element={<Findings />} />
          <Route path="triage" element={<Triage />} />
          <Route path="triage/:cveId" element={<TriageDetail />} />
          <Route path="assessments" element={<Assessments />} />
          <Route path="statistics" element={<Statistics />} />
          <Route path="reports" element={<Reports />} />
          <Route path="oval-database" element={<OVALDatabase />} />
          <Route path="admin" element={<AdminRoute><Admin /></AdminRoute>} />
          <Route
            path="admin/server-groups/:id/members"
            element={<AdminRoute><ServerGroupMembers /></AdminRoute>}
          />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
