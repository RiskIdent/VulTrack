import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams, useNavigate, useBlocker } from 'react-router-dom';
import { ArrowLeft, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Search, Save } from 'lucide-react';
import { getServerGroup, getServerGroupMembers, getServers, setServerGroupMembers } from '../api/client';
import type { Server as ServerType, ServerGroup } from '../types';

// Dual-list ("transfer list") view for managing the members of a single server group.
// Reachable via /admin/server-groups/:id/members. Stages all changes locally and
// commits them with a single bulk PUT on Save.
export default function ServerGroupMembers() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const groupId = id ? parseInt(id, 10) : NaN;

  const [group, setGroup] = useState<ServerGroup | null>(null);
  const [allServers, setAllServers] = useState<ServerType[]>([]);
  const [initialMemberIds, setInitialMemberIds] = useState<Set<number>>(new Set());
  const [memberIds, setMemberIds] = useState<Set<number>>(new Set());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Selection state per pane
  const [selectedAvail, setSelectedAvail] = useState<Set<number>>(new Set());
  const [selectedMember, setSelectedMember] = useState<Set<number>>(new Set());
  const lastClickedAvail = useRef<number | null>(null);
  const lastClickedMember = useRef<number | null>(null);

  // Search state per pane
  const [searchAvail, setSearchAvail] = useState('');
  const [searchMember, setSearchMember] = useState('');

  useEffect(() => {
    if (Number.isNaN(groupId)) {
      setError('Invalid group ID');
      setLoading(false);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const [grp, mem, srv] = await Promise.all([
          getServerGroup(groupId),
          getServerGroupMembers(groupId),
          getServers(),
        ]);
        if (cancelled) return;
        setGroup(grp);
        const ids = new Set((mem.servers ?? []).map((s) => s.id));
        setInitialMemberIds(ids);
        setMemberIds(new Set(ids));
        setAllServers(srv.servers ?? []);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load group');
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [groupId]);

  const dirty = useMemo(() => {
    if (initialMemberIds.size !== memberIds.size) return true;
    for (const id of initialMemberIds) if (!memberIds.has(id)) return true;
    return false;
  }, [initialMemberIds, memberIds]);

  // Warn before navigating away with unsaved changes.
  const blocker = useBlocker(dirty && !saving);
  useEffect(() => {
    if (blocker.state === 'blocked') {
      const proceed = window.confirm('You have unsaved changes. Leave this page anyway?');
      if (proceed) blocker.proceed();
      else blocker.reset();
    }
  }, [blocker]);
  // Browser-level beforeunload (closing tab / reloading).
  useEffect(() => {
    if (!dirty) return;
    const handler = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => window.removeEventListener('beforeunload', handler);
  }, [dirty]);

  // Filtered + sorted lists for each pane.
  const matches = (s: ServerType, q: string) => {
    if (!q) return true;
    const query = q.toLowerCase();
    return (
      s.name.toLowerCase().includes(query) ||
      (s.osFamily ?? '').toLowerCase().includes(query) ||
      (s.osRelease ?? '').toLowerCase().includes(query) ||
      (s.ipv4Addrs ?? []).some((ip) => ip.includes(query))
    );
  };

  const availableList = useMemo(
    () =>
      allServers
        .filter((s) => !memberIds.has(s.id) && matches(s, searchAvail))
        .sort((a, b) => a.name.localeCompare(b.name)),
    [allServers, memberIds, searchAvail],
  );
  const memberList = useMemo(
    () =>
      allServers
        .filter((s) => memberIds.has(s.id) && matches(s, searchMember))
        .sort((a, b) => a.name.localeCompare(b.name)),
    [allServers, memberIds, searchMember],
  );

  // Click handler with shift-click range and ctrl/cmd-click toggle support.
  const handleRowClick = (
    server: ServerType,
    list: ServerType[],
    selected: Set<number>,
    setSelected: (s: Set<number>) => void,
    lastClickedRef: React.MutableRefObject<number | null>,
    e: React.MouseEvent,
  ) => {
    const next = new Set(selected);
    const idx = list.findIndex((s) => s.id === server.id);

    if (e.shiftKey && lastClickedRef.current !== null) {
      const prevIdx = list.findIndex((s) => s.id === lastClickedRef.current);
      if (prevIdx !== -1) {
        const [from, to] = prevIdx < idx ? [prevIdx, idx] : [idx, prevIdx];
        for (let i = from; i <= to; i++) next.add(list[i].id);
        setSelected(next);
        return;
      }
    }

    if (e.ctrlKey || e.metaKey) {
      if (next.has(server.id)) next.delete(server.id);
      else next.add(server.id);
    } else {
      // Plain click: toggle, but treat as primary selection (anchor for next shift-click).
      if (next.has(server.id) && next.size === 1) {
        next.delete(server.id);
      } else {
        next.clear();
        next.add(server.id);
      }
    }
    setSelected(next);
    lastClickedRef.current = server.id;
  };

  const toggleSelectAll = (list: ServerType[], selected: Set<number>, setSelected: (s: Set<number>) => void) => {
    const visibleIds = list.map((s) => s.id);
    const allSelected = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));
    const next = new Set(selected);
    if (allSelected) {
      visibleIds.forEach((id) => next.delete(id));
    } else {
      visibleIds.forEach((id) => next.add(id));
    }
    setSelected(next);
  };

  const moveSelectedRight = () => {
    if (selectedAvail.size === 0) return;
    const next = new Set(memberIds);
    selectedAvail.forEach((id) => next.add(id));
    setMemberIds(next);
    setSelectedAvail(new Set());
    lastClickedAvail.current = null;
  };

  const moveSelectedLeft = () => {
    if (selectedMember.size === 0) return;
    const next = new Set(memberIds);
    selectedMember.forEach((id) => next.delete(id));
    setMemberIds(next);
    setSelectedMember(new Set());
    lastClickedMember.current = null;
  };

  const moveAllVisibleRight = () => {
    if (availableList.length === 0) return;
    const next = new Set(memberIds);
    availableList.forEach((s) => next.add(s.id));
    setMemberIds(next);
    setSelectedAvail(new Set());
  };

  const moveAllVisibleLeft = () => {
    if (memberList.length === 0) return;
    const next = new Set(memberIds);
    memberList.forEach((s) => next.delete(s.id));
    setMemberIds(next);
    setSelectedMember(new Set());
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await setServerGroupMembers(groupId, Array.from(memberIds));
      // Treat current state as the new baseline so the leave-warning resets.
      setInitialMemberIds(new Set(memberIds));
      navigate('/admin', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save group members');
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading group...</div>;
  }

  if (!group) {
    return (
      <div className="space-y-4">
        <div className="text-red-400">{error || 'Group not found'}</div>
        <Link to="/admin" className="text-[#4ade80] hover:underline">Back to Admin</Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link
            to="/admin"
            className="p-2 rounded-lg text-[#a5d6a7] hover:bg-[#1a2420] hover:text-[#e8f5e9]"
            title="Back to Admin"
          >
            <ArrowLeft className="w-5 h-5" />
          </Link>
          <div className="w-4 h-4 rounded" style={{ backgroundColor: group.color }} />
          <div>
            <h1 className="text-2xl font-bold text-[#e8f5e9]">{group.name}</h1>
            <p className="text-sm text-[#a5d6a7]">
              {group.description || 'Manage members of this server group.'}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => navigate('/admin')}
            className="btn btn-secondary"
            disabled={saving}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleSave}
            disabled={!dirty || saving}
            className="btn btn-primary flex items-center gap-2 disabled:opacity-50"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Hint row */}
      <div className="text-xs text-[#6b7280]">
        Click to select, Shift-click for a range, Ctrl/Cmd-click to toggle.
        {dirty && (
          <span className="ml-2 text-amber-400">Unsaved changes.</span>
        )}
      </div>

      {/* Two-pane layout */}
      <div className="grid grid-cols-[1fr_auto_1fr] gap-4 items-stretch">
        {/* Available */}
        <ServerListPane
          title="Available servers"
          subtitle={`${availableList.length} of ${allServers.length - memberIds.size}`}
          servers={availableList}
          selected={selectedAvail}
          onRowClick={(srv, e) =>
            handleRowClick(srv, availableList, selectedAvail, setSelectedAvail, lastClickedAvail, e)
          }
          onToggleAll={() => toggleSelectAll(availableList, selectedAvail, setSelectedAvail)}
          search={searchAvail}
          onSearchChange={setSearchAvail}
          emptyMessage={searchAvail ? 'No servers match your search' : 'No servers available'}
        />

        {/* Move buttons */}
        <div className="flex flex-col items-center justify-center gap-2 px-2">
          <button
            type="button"
            onClick={moveSelectedRight}
            disabled={selectedAvail.size === 0}
            className="btn btn-secondary p-2 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Add selected to group"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
          <button
            type="button"
            onClick={moveAllVisibleRight}
            disabled={availableList.length === 0}
            className="btn btn-secondary p-2 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Add all visible to group"
          >
            <ChevronsRight className="w-5 h-5" />
          </button>
          <button
            type="button"
            onClick={moveAllVisibleLeft}
            disabled={memberList.length === 0}
            className="btn btn-secondary p-2 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Remove all visible from group"
          >
            <ChevronsLeft className="w-5 h-5" />
          </button>
          <button
            type="button"
            onClick={moveSelectedLeft}
            disabled={selectedMember.size === 0}
            className="btn btn-secondary p-2 disabled:opacity-30 disabled:cursor-not-allowed"
            title="Remove selected from group"
          >
            <ChevronLeft className="w-5 h-5" />
          </button>
        </div>

        {/* Members */}
        <ServerListPane
          title="Group members"
          subtitle={`${memberList.length} of ${memberIds.size}`}
          servers={memberList}
          selected={selectedMember}
          onRowClick={(srv, e) =>
            handleRowClick(srv, memberList, selectedMember, setSelectedMember, lastClickedMember, e)
          }
          onToggleAll={() => toggleSelectAll(memberList, selectedMember, setSelectedMember)}
          search={searchMember}
          onSearchChange={setSearchMember}
          emptyMessage={searchMember ? 'No servers match your search' : 'No servers in this group yet'}
        />
      </div>
    </div>
  );
}

interface PaneProps {
  title: string;
  subtitle: string;
  servers: ServerType[];
  selected: Set<number>;
  onRowClick: (server: ServerType, e: React.MouseEvent) => void;
  onToggleAll: () => void;
  search: string;
  onSearchChange: (q: string) => void;
  emptyMessage: string;
}

function ServerListPane({
  title,
  subtitle,
  servers,
  selected,
  onRowClick,
  onToggleAll,
  search,
  onSearchChange,
  emptyMessage,
}: PaneProps) {
  const allVisibleSelected = servers.length > 0 && servers.every((s) => selected.has(s.id));
  const someVisibleSelected = servers.some((s) => selected.has(s.id));

  return (
    <div className="card flex flex-col min-h-[480px] max-h-[calc(100vh-280px)]">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h2 className="text-sm font-semibold text-[#e8f5e9]">{title}</h2>
          <p className="text-xs text-[#6b7280]">{subtitle}</p>
        </div>
        <label className="flex items-center gap-2 cursor-pointer text-xs text-[#a5d6a7]">
          <input
            type="checkbox"
            checked={allVisibleSelected}
            ref={(el) => {
              if (el) el.indeterminate = !allVisibleSelected && someVisibleSelected;
            }}
            onChange={onToggleAll}
            className="w-4 h-4 rounded border-[#2d3f36] bg-[#0a0f0d] text-[#4ade80] focus:ring-[#4ade80]"
            disabled={servers.length === 0}
          />
          Select all visible
        </label>
      </div>

      <div className="relative mb-3">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280]" />
        <input
          type="text"
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search by name, OS, or IP…"
          className="w-full pl-10 pr-4 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
        />
      </div>

      <div className="flex-1 overflow-y-auto border border-[#2d3f36] rounded-lg divide-y divide-[#2d3f36]">
        {servers.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-[#6b7280]">{emptyMessage}</div>
        ) : (
          servers.map((server) => {
            const isSelected = selected.has(server.id);
            return (
              <button
                key={server.id}
                type="button"
                onClick={(e) => onRowClick(server, e)}
                className={`w-full flex items-center justify-between px-4 py-2 text-left transition-colors ${
                  isSelected
                    ? 'bg-[#4ade80]/10 hover:bg-[#4ade80]/15'
                    : 'hover:bg-[#1a2420]'
                }`}
              >
                <div className="min-w-0">
                  <div className={`font-medium truncate ${isSelected ? 'text-[#4ade80]' : 'text-[#e8f5e9]'}`}>
                    {server.name}
                  </div>
                  <div className="text-xs text-[#6b7280] truncate">
                    {server.osFamily} {server.osRelease} • {server.ipv4Addrs?.[0] || 'No IP'}
                  </div>
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
