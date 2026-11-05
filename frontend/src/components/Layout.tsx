import { ReactNode, useEffect, useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import {
  LayoutDashboard,
  Server,
  Shield,
  ClipboardCheck,
  BarChart3,
  Terminal,
  Settings,
  FileCheck,
  FileText,
  Database,
  LogOut,
  User,
  Radar,
  Sparkles,
  Package,
  Bot,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

interface LayoutProps {
  children?: ReactNode;
}

interface NavLink {
  path: string;
  label: string;
  icon: LucideIcon;
  adminOnly?: boolean;
}

// A group shows its pages as an indented sub-menu.
interface NavGroup {
  id: string;
  label: string;
  icon: LucideIcon;
  children: NavLink[];
}

type NavEntry = NavLink | NavGroup;

const navItems: NavEntry[] = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/servers', label: 'Servers', icon: Server },
  { path: '/scans', label: 'Scans', icon: Radar },
  { path: '/findings', label: 'Findings', icon: Shield },
  { path: '/packages', label: 'APT Packages', icon: Package },
  {
    id: 'triage',
    label: 'Triage',
    icon: ClipboardCheck,
    children: [
      { path: '/triage', label: 'Queue', icon: ClipboardCheck },
      { path: '/assessments', label: 'Assessments', icon: FileCheck },
      { path: '/auto-decisions', label: 'Auto Decisions', icon: Bot },
      { path: '/ai-assessments', label: 'AI Assessments', icon: Sparkles },
    ],
  },
  { path: '/statistics', label: 'Statistics', icon: BarChart3 },
  { path: '/reports', label: 'Reports', icon: FileText },
  { path: '/oval-database', label: 'OVAL Database', icon: Database },
  { path: '/admin', label: 'Admin', icon: Settings, adminOnly: true },
];

const isGroup = (e: NavEntry): e is NavGroup => 'children' in e;

const isActivePath = (pathname: string, path: string) =>
  pathname === path || (path !== '/' && pathname.startsWith(path + '/'));

const GROUPS_STORAGE_KEY = 'vultrack.nav.openGroups';

function readOpenGroups(): string[] {
  try {
    return JSON.parse(window.localStorage.getItem(GROUPS_STORAGE_KEY) || '[]');
  } catch {
    return [];
  }
}

export default function Layout({ children }: LayoutProps) {
  const content = children ?? <Outlet />;
  const location = useLocation();
  const { user, authEnabled, logout } = useAuth();

  // Groups the user opened; a group with the current page is always open.
  const [openGroups, setOpenGroups] = useState<string[]>(readOpenGroups);
  useEffect(() => {
    try {
      window.localStorage.setItem(GROUPS_STORAGE_KEY, JSON.stringify(openGroups));
    } catch {
      // storage unavailable: the menu still works, it just forgets
    }
  }, [openGroups]);
  const toggleGroup = (id: string) =>
    setOpenGroups((prev) => (prev.includes(id) ? prev.filter((g) => g !== id) : [...prev, id]));

  return (
    <div className="min-h-screen bg-[#0a0f0d] flex">
      {/* Sidebar */}
      <aside className="w-64 bg-[#111916] border-r border-[#2d3f36] flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-[#2d3f36]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-[#4ade80]/20 rounded-lg flex items-center justify-center">
              <Terminal className="w-6 h-6 text-[#4ade80]" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-[#e8f5e9]">VulTrack</h1>
              <p className="text-xs text-[#6b7280]">Vulnerability Management</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4">
          <ul className="space-y-2">
            {navItems.map((entry) => {
              if (isGroup(entry)) {
                const children = entry.children.filter((c) => !c.adminOnly || user?.isAdmin);
                const childActive = children.some((c) => isActivePath(location.pathname, c.path));
                const open = childActive || openGroups.includes(entry.id);
                const GroupIcon = entry.icon;
                return (
                  <li key={entry.id}>
                    <button
                      type="button"
                      onClick={() => toggleGroup(entry.id)}
                      aria-expanded={open}
                      className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                        childActive ? 'text-[#4ade80]' : 'text-[#a5d6a7] hover:bg-[#1a2420] hover:text-[#e8f5e9]'
                      }`}
                    >
                      <GroupIcon className="w-5 h-5" />
                      <span className="text-sm font-medium flex-1 text-left">{entry.label}</span>
                      {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </button>
                    {open && (
                      <ul className="mt-1 ml-5 pl-3 border-l border-[#2d3f36] space-y-1">
                        {children.map((child) => {
                          const active = isActivePath(location.pathname, child.path);
                          return (
                            <li key={child.path}>
                              <Link
                                to={child.path}
                                className={`block px-3 py-2 rounded-lg text-sm transition-all duration-200 ${
                                  active
                                    ? 'bg-[#4ade80]/10 text-[#4ade80] border border-[#4ade80]/30'
                                    : 'text-[#a5d6a7] hover:bg-[#1a2420] hover:text-[#e8f5e9]'
                                }`}
                              >
                                {child.label}
                              </Link>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </li>
                );
              }

              if (entry.adminOnly && !user?.isAdmin) return null;
              const isActive = isActivePath(location.pathname, entry.path);
              const Icon = entry.icon;
              return (
                <li key={entry.path}>
                  <Link
                    to={entry.path}
                    className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 ${
                      isActive
                        ? 'bg-[#4ade80]/10 text-[#4ade80] border border-[#4ade80]/30'
                        : 'text-[#a5d6a7] hover:bg-[#1a2420] hover:text-[#e8f5e9]'
                    }`}
                  >
                    <Icon className="w-5 h-5" />
                    <span className="text-sm font-medium">{entry.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        {/* User / Auth */}
        <div className="p-4 border-t border-[#2d3f36] space-y-2">
          {user ? (
            <div className="flex flex-col gap-2">
              <div className="flex items-center gap-2 text-sm text-[#a5d6a7]">
                <User className="w-4 h-4 shrink-0" />
                <span className="truncate" title={user.email}>
                  {user.name || user.email}
                </span>
              </div>
              <button
                type="button"
                onClick={() => logout()}
                className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-[#6b7280] hover:bg-[#1a2420] hover:text-[#a5d6a7] transition-colors w-full"
              >
                <LogOut className="w-4 h-4" />
                Logout
              </button>
            </div>
          ) : authEnabled ? (
            <Link
              to="/login"
              className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-[#4ade80] hover:bg-[#1a2420] transition-colors"
            >
              <User className="w-4 h-4" />
              Sign in
            </Link>
          ) : null}
          <div className="text-xs text-[#6b7280]">
            <p>VulTrack {__APP_VERSION__}</p>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="p-8">
          {content}
        </div>
      </main>
    </div>
  );
}
