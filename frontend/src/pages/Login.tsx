import { Terminal } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { authEnabled, loading, login } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0a0f0d] flex items-center justify-center">
        <div className="text-[#a5d6a7]">Loading...</div>
      </div>
    );
  }

  if (!authEnabled) {
    return (
      <div className="min-h-screen bg-[#0a0f0d] flex items-center justify-center">
        <div className="text-[#a5d6a7]">Authentication is disabled.</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0a0f0d] flex items-center justify-center p-4">
      <div className="w-full max-w-sm rounded-xl bg-[#111916] border border-[#2d3f36] p-8 shadow-xl">
        <div className="flex flex-col items-center gap-6">
          <div className="w-14 h-14 bg-[#4ade80]/20 rounded-xl flex items-center justify-center">
            <Terminal className="w-8 h-8 text-[#4ade80]" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold text-[#e8f5e9]">VulTrack</h1>
            <p className="text-sm text-[#6b7280] mt-1">Vulnerability Management</p>
          </div>
          <p className="text-sm text-[#a5d6a7] text-center">
            Sign in with your organization account to continue.
          </p>
          <button
            type="button"
            onClick={login}
            className="w-full py-3 px-4 rounded-lg bg-[#4ade80]/20 text-[#4ade80] font-medium border border-[#4ade80]/30 hover:bg-[#4ade80]/30 transition-colors"
          >
            Sign in with SSO
          </button>
        </div>
      </div>
    </div>
  );
}
