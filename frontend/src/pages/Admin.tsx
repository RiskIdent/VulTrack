import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Settings, FileText, Server, Users, Save, Plus, Pencil, Trash2, X, Check, Search, Key, Shield, Database, RefreshCw, AlertCircle, CheckCircle2, Clock, ChevronUp, ChevronDown, ChevronLeft, ChevronRight, ClipboardCheck, AlertTriangle, RotateCcw } from 'lucide-react';
import { ConfirmModal } from '../components/ConfirmModal';
import {
  getSettings,
  updateSettings,
  getReasonTemplates,
  createReasonTemplate,
  updateReasonTemplate,
  deleteReasonTemplate,
  getServerGroups,
  createServerGroup,
  updateServerGroup,
  deleteServerGroup,
  getServers,
  deleteServer,
  // New imports for agent-based architecture
  getEnrollmentKeys,
  createEnrollmentKey,
  deleteEnrollmentKey,
  getRegisteredAgents,
  approveAgent,
  revokeAgent,
  deleteAgent,
  getOVALSources,
  getOVALDistributions,
  enableOVALSource,
  deleteOVALSource,
  triggerOVALSync,
  getNVDStatus,
  triggerNVDSync,
  getExploitDBStatus,
  triggerExploitDBSync,
  getVEXStatus,
  triggerVEXSync,
  getAdminUsers,
  updateUserAdmin,
} from '../api/client';
import type { AdminUser } from '../api/client';
import type { Setting, ReasonTemplate, ServerGroup, Server as ServerType } from '../types';
import type { EnrollmentKey, RegisteredAgent, OVALSource } from '../api/client';

type TabType = 'triage' | 'templates' | 'groups' | 'oval' | 'agents' | 'keys' | 'datasources' | 'users' | 'reset' | 'servers';

export default function Admin() {
  const [activeTab, setActiveTab] = useState<TabType>('triage');

  const tabs = [
    { id: 'triage' as TabType, label: 'Triage', icon: ClipboardCheck },
    { id: 'oval' as TabType, label: 'OVAL Sources', icon: Shield },
    { id: 'datasources' as TabType, label: 'Data Sources', icon: Database },
    { id: 'agents' as TabType, label: 'Agents', icon: Server },
    { id: 'keys' as TabType, label: 'Enrollment Keys', icon: Key },
    { id: 'groups' as TabType, label: 'Server Groups', icon: Server },
    { id: 'servers' as TabType, label: 'Servers', icon: Server },
    { id: 'templates' as TabType, label: 'Templates', icon: FileText },
    { id: 'users' as TabType, label: 'Users', icon: Users },
    { id: 'reset' as TabType, label: 'Reset', icon: RotateCcw },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-[#e8f5e9]">Administration</h1>
        <p className="text-[#a5d6a7] mt-1">Manage VulTrack settings and configuration</p>
      </div>

      {/* Tabs */}
      <div className="border-b border-[#2d3f36]">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors
                  ${activeTab === tab.id
                    ? 'border-[#4ade80] text-[#4ade80]'
                    : 'border-transparent text-[#6b7280] hover:text-[#a5d6a7] hover:border-[#2d3f36]'
                  }
                `}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="mt-6">
        {activeTab === 'triage' && <TriageSettingsTab />}
        {activeTab === 'oval' && <OVALSourcesTab />}
        {activeTab === 'datasources' && <DataSourcesTab />}
        {activeTab === 'agents' && <AgentsTab />}
        {activeTab === 'keys' && <EnrollmentKeysTab />}
        {activeTab === 'groups' && <ServerGroupsTab />}
        {activeTab === 'servers' && <ServerManagementTab />}
        {activeTab === 'templates' && <ReasonTemplatesTab />}
        {activeTab === 'users' && <UsersTab />}
        {activeTab === 'reset' && <ResetTab />}
      </div>
    </div>
  );
}

// Triage Settings Tab
function TriageSettingsTab() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [editedValues, setEditedValues] = useState<Record<string, string>>({});

  useEffect(() => {
    fetchSettings();
  }, []);

  async function fetchSettings() {
    try {
      const data = await getSettings();
      const values: Record<string, string> = {};
      (data.settings || []).forEach((s: Setting) => {
        values[s.key] = s.value;
      });
      setEditedValues(values);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load settings');
    } finally {
      setLoading(false);
    }
  }

  async function handleSave() {
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      await updateSettings(editedValues);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading settings...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Triage Settings</h2>
        
        {error && (
          <div className="mb-4 p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
            {error}
          </div>
        )}
        
        {success && (
          <div className="mb-4 p-3 bg-green-600/10 border border-green-600/50 rounded-lg text-green-400">
            Settings saved successfully!
          </div>
        )}

        <div className="space-y-6">
          {/* Filter Mode Selection */}
          <div>
            <label className="block text-sm font-medium text-[#a5d6a7] mb-2">
              Triage Queue Filter Mode
            </label>
            <p className="text-xs text-[#6b7280] mb-3">
              Choose how findings are selected for the triage queue.
            </p>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="triage_filter_mode"
                  value="cvss"
                  checked={editedValues['triage_filter_mode'] !== 'vendor_severity'}
                  onChange={() => setEditedValues({ ...editedValues, triage_filter_mode: 'cvss' })}
                  className="w-4 h-4 text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                />
                <span className="text-[#e8f5e9]">CVSS Score</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="radio"
                  name="triage_filter_mode"
                  value="vendor_severity"
                  checked={editedValues['triage_filter_mode'] === 'vendor_severity'}
                  onChange={() => setEditedValues({ ...editedValues, triage_filter_mode: 'vendor_severity' })}
                  className="w-4 h-4 text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                />
                <span className="text-[#e8f5e9]">Vendor Severity</span>
              </label>
            </div>
          </div>

          {/* CVSS Threshold (shown when CVSS mode selected) */}
          {editedValues['triage_filter_mode'] !== 'vendor_severity' && (
            <div className="pl-6 border-l-2 border-[#2d3f36]">
              <label className="block text-sm font-medium text-[#a5d6a7] mb-2">
                CVSS Score Threshold
              </label>
              <p className="text-xs text-[#6b7280] mb-2">
                Findings with a CVSS score equal to or higher than this value will appear in the triage queue.
              </p>
              <input
                type="number"
                step="0.1"
                min="0"
                max="10"
                value={editedValues['triage_cvss_threshold'] || '7.0'}
                onChange={(e) => setEditedValues({ ...editedValues, triage_cvss_threshold: e.target.value })}
                className="w-32 px-3 py-2 bg-[#1a2420] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
              />
            </div>
          )}

          {/* Vendor Severity Options (shown when Vendor Severity mode selected) */}
          {editedValues['triage_filter_mode'] === 'vendor_severity' && (
            <div className="pl-6 border-l-2 border-[#2d3f36] space-y-4">
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-2">
                  Included Severities
                </label>
                <p className="text-xs text-[#6b7280] mb-3">
                  Select which vendor severity levels should appear in the triage queue.
                </p>
                <div className="flex flex-wrap gap-3">
                  {['critical', 'high', 'medium', 'low'].map((severity) => {
                    const currentSeverities = (editedValues['triage_vendor_severities'] || 'critical,high').split(',').map(s => s.trim().toLowerCase());
                    const isChecked = currentSeverities.includes(severity);
                    return (
                      <label key={severity} className="flex items-center gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={isChecked}
                          onChange={(e) => {
                            let newSeverities = currentSeverities.filter(s => s !== '');
                            if (e.target.checked) {
                              if (!newSeverities.includes(severity)) {
                                newSeverities.push(severity);
                              }
                            } else {
                              newSeverities = newSeverities.filter(s => s !== severity);
                            }
                            setEditedValues({ ...editedValues, triage_vendor_severities: newSeverities.join(',') });
                          }}
                          className="w-4 h-4 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                        />
                        <span className={`text-sm font-medium px-2 py-0.5 rounded ${
                          severity === 'critical' ? 'bg-red-600/20 text-red-400' :
                          severity === 'high' ? 'bg-orange-600/20 text-orange-400' :
                          severity === 'medium' ? 'bg-yellow-600/20 text-yellow-400' :
                          'bg-green-600/20 text-green-400'
                        }`}>
                          {severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>

              <div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={editedValues['triage_include_unrated'] === 'true'}
                    onChange={(e) => setEditedValues({ ...editedValues, triage_include_unrated: e.target.checked ? 'true' : 'false' })}
                    className="w-4 h-4 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
                  />
                  <span className="text-[#e8f5e9]">Include findings without vendor severity</span>
                </label>
                <p className="text-xs text-[#6b7280] mt-1 ml-6">
                  When enabled, findings that have no vendor severity rating will also appear in the triage queue.
                </p>
              </div>
            </div>
          )}

          {/* VEX Filter */}
          <div>
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={editedValues['triage_hide_vex_not_affected'] !== 'false'}
                onChange={(e) => setEditedValues({ ...editedValues, triage_hide_vex_not_affected: e.target.checked ? 'true' : 'false' })}
                className="w-4 h-4 rounded text-[#4ade80] bg-[#1a2420] border-[#2d3f36] focus:ring-[#4ade80]"
              />
              <span className="text-[#e8f5e9]">Hide "Not Affected" (VEX)</span>
            </label>
            <p className="text-xs text-[#6b7280] mt-1 ml-6">
              When enabled, findings where Canonical's VEX data marks the package as not affected are excluded from the triage queue.
            </p>
          </div>
        </div>

        <div className="mt-6 pt-4 border-t border-[#2d3f36]">
          <button
            onClick={handleSave}
            disabled={saving}
            className="btn btn-primary flex items-center gap-2"
          >
            <Save className="w-4 h-4" />
            {saving ? 'Saving...' : 'Save Settings'}
          </button>
        </div>
      </div>
    </div>
  );
}

// Reason Templates Tab
function ReasonTemplatesTab() {
  const [templates, setTemplates] = useState<ReasonTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState({ reason: '', appliesTo: 'both', sortOrder: 0 });
  const [showNewForm, setShowNewForm] = useState(false);
  const [newForm, setNewForm] = useState({ reason: '', appliesTo: 'both', sortOrder: 100 });
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; template: ReasonTemplate | null }>({ isOpen: false, template: null });

  useEffect(() => {
    fetchTemplates();
  }, []);

  async function fetchTemplates() {
    try {
      const data = await getReasonTemplates();
      setTemplates(data.templates || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load templates');
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate() {
    try {
      await createReasonTemplate({
        reason: newForm.reason,
        appliesTo: newForm.appliesTo,
        sortOrder: newForm.sortOrder,
      });
      setShowNewForm(false);
      setNewForm({ reason: '', appliesTo: 'both', sortOrder: 100 });
      fetchTemplates();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create template');
    }
  }

  async function handleUpdate(id: number) {
    try {
      await updateReasonTemplate(id, {
        reason: editForm.reason,
        appliesTo: editForm.appliesTo,
        isActive: true,
        sortOrder: editForm.sortOrder,
      });
      setEditingId(null);
      fetchTemplates();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update template');
    }
  }

  function openDeleteModal(template: ReasonTemplate) {
    setDeleteModal({ isOpen: true, template });
  }

  async function confirmDelete() {
    if (!deleteModal.template) return;
    const templateId = deleteModal.template.id;
    setDeleteModal({ isOpen: false, template: null });
    try {
      await deleteReasonTemplate(templateId);
      fetchTemplates();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete template');
    }
  }

  function startEdit(template: ReasonTemplate) {
    setEditingId(template.id);
    setEditForm({
      reason: template.reason,
      appliesTo: template.appliesTo,
      sortOrder: template.sortOrder,
    });
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading templates...</div>;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Reason Templates</h2>
          <button
            onClick={() => setShowNewForm(true)}
            className="btn btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add Template
          </button>
        </div>

        <p className="text-sm text-[#6b7280] mb-4">
          These templates provide quick options when assessing findings in the triage queue.
        </p>

        {/* New Template Form */}
        {showNewForm && (
          <div className="mb-4 p-4 bg-[#1a2420] border border-[#2d3f36] rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Reason</label>
                <input
                  type="text"
                  value={newForm.reason}
                  onChange={(e) => setNewForm({ ...newForm, reason: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                  placeholder="Enter reason text..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Applies To</label>
                <select
                  value={newForm.appliesTo}
                  onChange={(e) => setNewForm({ ...newForm, appliesTo: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                >
                  <option value="both">Both</option>
                  <option value="not_relevant">Not Relevant</option>
                  <option value="accepted_risk">Accept Risk</option>
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowNewForm(false)}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!newForm.reason.trim()}
                className="btn btn-primary"
              >
                Create
              </button>
            </div>
          </div>
        )}

        {/* Templates Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4">Reason</th>
                <th className="table-header text-left py-3 px-4 w-40">Applies To</th>
                <th className="table-header text-left py-3 px-4 w-24">Order</th>
                <th className="table-header text-right py-3 px-4 w-24">Actions</th>
              </tr>
            </thead>
            <tbody>
              {templates.map((template) => (
                <tr key={template.id} className="table-row">
                  {editingId === template.id ? (
                    <>
                      <td className="py-2 px-4">
                        <input
                          type="text"
                          value={editForm.reason}
                          onChange={(e) => setEditForm({ ...editForm, reason: e.target.value })}
                          className="w-full px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                        />
                      </td>
                      <td className="py-2 px-4">
                        <select
                          value={editForm.appliesTo}
                          onChange={(e) => setEditForm({ ...editForm, appliesTo: e.target.value })}
                          className="w-full px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                        >
                          <option value="both">Both</option>
                          <option value="not_relevant">Not Relevant</option>
                          <option value="accepted_risk">Accept Risk</option>
                        </select>
                      </td>
                      <td className="py-2 px-4">
                        <input
                          type="number"
                          value={editForm.sortOrder}
                          onChange={(e) => setEditForm({ ...editForm, sortOrder: parseInt(e.target.value) || 0 })}
                          className="w-full px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                        />
                      </td>
                      <td className="py-2 px-4 text-right">
                        <button onClick={() => handleUpdate(template.id)} className="p-1 text-green-400 hover:text-green-300">
                          <Check className="w-4 h-4" />
                        </button>
                        <button onClick={() => setEditingId(null)} className="p-1 text-[#6b7280] hover:text-[#a5d6a7] ml-1">
                          <X className="w-4 h-4" />
                        </button>
                      </td>
                    </>
                  ) : (
                    <>
                      <td className="py-3 px-4 text-[#e8f5e9]">{template.reason}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${
                          template.appliesTo === 'both'
                            ? 'bg-blue-600/20 text-blue-400'
                            : template.appliesTo === 'not_relevant'
                            ? 'bg-green-600/20 text-green-400'
                            : 'bg-yellow-600/20 text-yellow-400'
                        }`}>
                          {template.appliesTo === 'both' ? 'Both' : 
                           template.appliesTo === 'not_relevant' ? 'Not Relevant' : 'Accept Risk'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-[#6b7280]">{template.sortOrder}</td>
                      <td className="py-3 px-4 text-right">
                        <button onClick={() => startEdit(template)} className="p-1 text-[#6b7280] hover:text-[#4ade80]">
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button onClick={() => openDeleteModal(template)} className="p-1 text-[#6b7280] hover:text-red-400 ml-1">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </>
                  )}
                </tr>
              ))}
              {templates.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[#6b7280]">
                    No templates defined. Click "Add Template" to create one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Template"
        message={deleteModal.template 
          ? `Are you sure you want to delete the template "${deleteModal.template.reason}"?`
          : ''
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setDeleteModal({ isOpen: false, template: null })}
      />
    </div>
  );
}

// Server Groups Tab
function ServerGroupsTab() {
  const [groups, setGroups] = useState<ServerGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);
  const [newForm, setNewForm] = useState({ name: '', description: '', color: '#4ade80' });
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState({ name: '', description: '', color: '#4ade80' });
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; group: ServerGroup | null }>({ isOpen: false, group: null });

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    try {
      const groupsData = await getServerGroups();
      setGroups(groupsData.groups || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load groups');
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate() {
    try {
      await createServerGroup(newForm);
      setShowNewForm(false);
      setNewForm({ name: '', description: '', color: '#4ade80' });
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create group');
    }
  }

  async function handleUpdate(id: number) {
    try {
      await updateServerGroup(id, editForm);
      setEditingId(null);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update group');
    }
  }

  function openDeleteModal(group: ServerGroup) {
    setDeleteModal({ isOpen: true, group });
  }

  async function confirmDelete() {
    if (!deleteModal.group) return;
    const groupId = deleteModal.group.id;
    setDeleteModal({ isOpen: false, group: null });
    try {
      await deleteServerGroup(groupId);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete group');
    }
  }

  function startEdit(group: ServerGroup) {
    setEditingId(group.id);
    setEditForm({
      name: group.name,
      description: group.description,
      color: group.color,
    });
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading server groups...</div>;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Server Groups</h2>
          <button
            onClick={() => setShowNewForm(true)}
            className="btn btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Add Group
          </button>
        </div>

        {/* New Group Form */}
        {showNewForm && (
          <div className="mb-4 p-4 bg-[#1a2420] border border-[#2d3f36] rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Name</label>
                <input
                  type="text"
                  value={newForm.name}
                  onChange={(e) => setNewForm({ ...newForm, name: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                  placeholder="Group name..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Description</label>
                <input
                  type="text"
                  value={newForm.description}
                  onChange={(e) => setNewForm({ ...newForm, description: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                  placeholder="Optional description..."
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Color</label>
                <input
                  type="color"
                  value={newForm.color}
                  onChange={(e) => setNewForm({ ...newForm, color: e.target.value })}
                  className="w-full h-10 px-1 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg cursor-pointer"
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowNewForm(false)}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!newForm.name.trim()}
                className="btn btn-primary"
              >
                Create
              </button>
            </div>
          </div>
        )}

        {/* Groups Table */}
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#2d3f36]">
                <th className="table-header text-left py-3 px-4 w-8"></th>
                <th className="table-header text-left py-3 px-4">Name</th>
                <th className="table-header text-left py-3 px-4">Description</th>
                <th className="table-header text-left py-3 px-4 w-24">Servers</th>
                <th className="table-header text-right py-3 px-4 w-32">Actions</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.id} className="table-row">
                  {editingId === group.id ? (
                    <>
                      <td className="py-2 px-4">
                        <input
                          type="color"
                          value={editForm.color}
                          onChange={(e) => setEditForm({ ...editForm, color: e.target.value })}
                          className="w-6 h-6 rounded cursor-pointer"
                        />
                      </td>
                      <td className="py-2 px-4">
                        <input
                          type="text"
                          value={editForm.name}
                          onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                          className="w-full px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                        />
                      </td>
                      <td className="py-2 px-4">
                        <input
                          type="text"
                          value={editForm.description}
                          onChange={(e) => setEditForm({ ...editForm, description: e.target.value })}
                          className="w-full px-2 py-1 bg-[#0a0f0d] border border-[#2d3f36] rounded text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                        />
                      </td>
                      <td className="py-2 px-4 text-[#6b7280]">{group.serverCount ?? 0}</td>
                      <td className="py-2 px-4 text-right">
                        <button onClick={() => handleUpdate(group.id)} className="p-1 text-green-400 hover:text-green-300">
                          <Check className="w-4 h-4" />
                        </button>
                        <button onClick={() => setEditingId(null)} className="p-1 text-[#6b7280] hover:text-[#a5d6a7] ml-1">
                          <X className="w-4 h-4" />
                        </button>
                      </td>
                    </>
                  ) : (
                    <>
                      <td className="py-3 px-4">
                        <div
                          className="w-4 h-4 rounded"
                          style={{ backgroundColor: group.color }}
                        />
                      </td>
                      <td className="py-3 px-4 text-[#e8f5e9] font-medium">{group.name}</td>
                      <td className="py-3 px-4 text-[#a5d6a7]">{group.description || '-'}</td>
                      <td className="py-3 px-4">
                        <Link
                          to={`/admin/server-groups/${group.id}/members`}
                          className="text-[#4ade80] hover:underline"
                        >
                          {group.serverCount ?? 0} servers
                        </Link>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          to={`/admin/server-groups/${group.id}/members`}
                          className="inline-block p-1 text-[#6b7280] hover:text-[#4ade80]"
                          title="Manage members"
                        >
                          <Server className="w-4 h-4" />
                        </Link>
                        <button onClick={() => startEdit(group)} className="p-1 text-[#6b7280] hover:text-[#4ade80] ml-1">
                          <Pencil className="w-4 h-4" />
                        </button>
                        <button onClick={() => openDeleteModal(group)} className="p-1 text-[#6b7280] hover:text-red-400 ml-1">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </>
                  )}
                </tr>
              ))}
              {groups.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-[#6b7280]">
                    No groups defined. Click "Add Group" to create one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Server Group"
        message={deleteModal.group 
          ? `Are you sure you want to delete the server group "${deleteModal.group.name}"? Servers will be removed from this group.`
          : ''
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setDeleteModal({ isOpen: false, group: null })}
      />
    </div>
  );
}

// ============================================================================
// OVAL Sources Tab (Ubuntu only)
// ============================================================================

interface UbuntuVersion {
  version: string;
  label: string;
}

function OVALSourcesTab() {
  const [sources, setSources] = useState<OVALSource[]>([]);
  const [ubuntuVersions, setUbuntuVersions] = useState<UbuntuVersion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState<number | null>(null);
  const [pendingSyncs, setPendingSyncs] = useState<Set<number>>(new Set()); // source IDs still syncing
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; source: OVALSource | null }>({ isOpen: false, source: null });

  useEffect(() => {
    fetchData();
  }, []);

  // Auto-refresh while syncs are pending
  useEffect(() => {
    if (pendingSyncs.size === 0) return;
    
    const interval = setInterval(() => {
      fetchData(true); // silent refresh
    }, 3000);
    
    return () => clearInterval(interval);
  }, [pendingSyncs]);

  async function fetchData(silent = false) {
    try {
      // On the first (non-silent) load we also pull the distribution catalog so
      // the version chips reflect whatever the backend's seed.sql offers — adding
      // a new Ubuntu release becomes a one-line seed change, no UI rebuild.
      const requests: Promise<unknown>[] = [getOVALSources()];
      if (!silent && ubuntuVersions.length === 0) {
        requests.push(getOVALDistributions());
      }
      const results = await Promise.all(requests);
      const srcData = results[0] as Awaited<ReturnType<typeof getOVALSources>>;
      const newSources = srcData.sources || [];
      setSources(newSources);

      if (results.length > 1) {
        const distData = results[1] as Awaited<ReturnType<typeof getOVALDistributions>>;
        const ubuntu = (distData.distributions || []).find(d => d.name === 'ubuntu');
        if (ubuntu) {
          setUbuntuVersions(
            ubuntu.versions.map(v => ({
              version: v.version,
              label: `${v.version}${v.lts ? ' LTS' : ''}${v.codename ? ` (${v.codename})` : ''}`,
            })),
          );
        }
      }

      // Remove source IDs from pending when that source has a recent lastSyncAt (sync just finished)
      const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
      setPendingSyncs(prev => {
        if (prev.size === 0) return prev;
        const next = new Set(prev);
        prev.forEach(sourceId => {
          const source = newSources.find((s: OVALSource) => s.id === sourceId);
          if (source?.lastSyncAt && new Date(source.lastSyncAt).getTime() >= fiveMinutesAgo) {
            next.delete(sourceId);
          }
        });
        return next;
      });
    } catch (err) {
      if (!silent) {
        setError(err instanceof Error ? err.message : 'Failed to load data');
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  }

  async function handleEnable(distribution: string, version: string) {
    try {
      await enableOVALSource({ distribution, version });
      const srcData = await getOVALSources();
      const newSources = srcData.sources || [];
      setSources(newSources);
      // Track which sources are syncing so table and version button show per-source state
      const idsForVersion = newSources
        .filter((s: OVALSource) => s.distribution === distribution && s.version === version)
        .map((s: OVALSource) => s.id);
      setPendingSyncs(prev => new Set([...prev, ...idsForVersion]));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to enable source');
    }
  }

  function openDeleteModal(source: OVALSource) {
    setDeleteModal({ isOpen: true, source });
  }

  async function confirmDelete() {
    if (!deleteModal.source) return;
    const sourceId = deleteModal.source.id;
    // Close modal immediately for better UX
    setDeleteModal({ isOpen: false, source: null });
    try {
      await deleteOVALSource(sourceId);
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete source');
    }
  }

  async function handleSync(id: number) {
    setSyncing(id);
    setPendingSyncs(prev => new Set(prev).add(id));
    try {
      await triggerOVALSync(id);
      fetchData();
    } catch (err) {
      setPendingSyncs(prev => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      setError(err instanceof Error ? err.message : 'Failed to trigger sync');
    } finally {
      setSyncing(null);
    }
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading OVAL sources...</div>;
  }

  // Group sources by distribution
  const sourcesByDist = sources.reduce((acc, src) => {
    if (!acc[src.distribution]) acc[src.distribution] = [];
    acc[src.distribution].push(src);
    return acc;
  }, {} as Record<string, OVALSource[]>);

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
        </div>
      )}

      {/* Enabled Sources */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Enabled OVAL Sources</h2>
        
        {sources.length === 0 ? (
          <p className="text-[#6b7280]">No OVAL sources enabled. Enable Ubuntu versions below.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  <th className="table-header text-left py-3 px-4">Distribution</th>
                  <th className="table-header text-left py-3 px-4">Version</th>
                  <th className="table-header text-left py-3 px-4">Last Sync</th>
                  <th className="table-header text-right py-3 px-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((src) => {
                  const isSyncing = pendingSyncs.has(src.id) || syncing === src.id;
                  return (
                    <tr key={src.id} className="table-row">
                      <td className="py-3 px-4 text-[#e8f5e9] font-medium capitalize">{src.distribution}</td>
                      <td className="py-3 px-4 text-[#a5d6a7]">
                        {src.version} {src.codename && `(${src.codename})`} {src.sourceType && ` ${src.sourceType.toUpperCase()}`}
                      </td>
                      <td className="py-3 px-4 text-sm">
                        {isSyncing ? (
                          <span className="text-yellow-400 flex items-center gap-1">
                            <RefreshCw className="w-3 h-3 animate-spin" />
                            Syncing...
                          </span>
                        ) : (
                          <span className="text-[#6b7280]">{formatDate(src.lastSyncAt)}</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleSync(src.id)}
                          disabled={isSyncing}
                          className="p-1 text-[#4ade80] hover:text-[#22c55e] disabled:opacity-50"
                          title="Sync now"
                        >
                          <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
                        </button>
                        <button
                          onClick={() => openDeleteModal(src)}
                          className="p-1 text-[#6b7280] hover:text-red-400 ml-2"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Ubuntu versions */}
      <div className="card">
        <h2 className="text-lg font-semibold text-[#e8f5e9] mb-4">Ubuntu versions</h2>
        <p className="text-sm text-[#6b7280] mb-4">
          Enable OVAL data for the Ubuntu versions you want to scan.
        </p>

        <div className="flex flex-wrap gap-2">
          {ubuntuVersions.length === 0 ? (
            <p className="text-sm text-[#6b7280]">No Ubuntu versions available.</p>
          ) : ubuntuVersions.map((v) => {
            const isEnabled = sourcesByDist['ubuntu']?.some(s => s.version === v.version);
            const ubuntuSourcesForVersion = sourcesByDist['ubuntu']?.filter(s => s.version === v.version) ?? [];
            const isSyncing = ubuntuSourcesForVersion.some(s => pendingSyncs.has(s.id));
            const disabled = isEnabled || isSyncing;
            return (
              <button
                key={v.version}
                onClick={() => !isEnabled && !isSyncing && handleEnable('ubuntu', v.version)}
                disabled={disabled}
                className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                  isEnabled
                    ? 'bg-[#4ade80]/20 text-[#4ade80] cursor-default'
                    : isSyncing
                    ? 'bg-yellow-600/20 text-yellow-400 cursor-wait'
                    : 'bg-[#1a2420] text-[#a5d6a7] hover:bg-[#2d3f36] hover:text-[#e8f5e9]'
                }`}
              >
                {isSyncing ? (
                  <RefreshCw className="w-3 h-3 inline mr-1 animate-spin" />
                ) : isEnabled ? (
                  <Check className="w-3 h-3 inline mr-1" />
                ) : null}
                {v.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete OVAL Source"
        message={deleteModal.source 
          ? `Are you sure you want to delete the OVAL source for ${deleteModal.source.distribution} ${deleteModal.source.version}? This will remove all cached vulnerability definitions for this source.`
          : ''
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setDeleteModal({ isOpen: false, source: null })}
      />
    </div>
  );
}

// ============================================================================
// Data Sources Tab (NVD + ExploitDB)
// ============================================================================

function DataSourcesTab() {
  const [nvdStatus, setNvdStatus] = useState<{
    syncing: boolean;
    lastSync: string | null;
    cveCount: number;
    hasApiKey: boolean;
  } | null>(null);
  const [exploitStatus, setExploitStatus] = useState<{
    syncing: boolean;
    lastSync: string | null;
    exploitCount: number;
    exploitsWithCve: number;
  } | null>(null);
  const [vexStatus, setVexStatus] = useState<{
    syncing: boolean;
    lastSync: string | null;
    statementCount: number;
    status?: string;
    error?: string;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Configuration state
  const [config, setConfig] = useState({
    nvd_api_key: '',
    nvd_sync_interval_hours: '6',
    exploitdb_sync_interval_hours: '24',
    vex_sync_interval_hours: '24',
  });
  const [showApiKey, setShowApiKey] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchStatus();
    fetchConfig();
    const interval = setInterval(fetchStatus, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  async function fetchConfig() {
    try {
      const data = await getSettings();
      const settings: Record<string, string> = {};
      (data.settings || []).forEach((s: Setting) => {
        if (['nvd_api_key', 'nvd_sync_interval_hours', 'exploitdb_sync_interval_hours', 'vex_sync_interval_hours'].includes(s.key)) {
          settings[s.key] = s.value;
        }
      });
      setConfig(prev => ({ ...prev, ...settings }));
    } catch (err) {
      // Silently fail - status is more important
    }
  }

  async function fetchStatus() {
    try {
      const [nvd, exploit, vex] = await Promise.all([
        getNVDStatus(),
        getExploitDBStatus(),
        getVEXStatus(),
      ]);
      setNvdStatus(nvd);
      setExploitStatus(exploit);
      setVexStatus(vex);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load status');
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveConfig() {
    setSaving(true);
    setError(null);
    setSuccess(null);
    try {
      await updateSettings(config);
      setSuccess('Configuration saved successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save configuration');
    } finally {
      setSaving(false);
    }
  }

  async function handleNVDSync() {
    try {
      await triggerNVDSync();
      setTimeout(fetchStatus, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger NVD sync');
    }
  }

  async function handleExploitDBSync() {
    try {
      await triggerExploitDBSync();
      setTimeout(fetchStatus, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger ExploitDB sync');
    }
  }

  async function handleVEXSync() {
    try {
      await triggerVEXSync();
      setTimeout(fetchStatus, 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to trigger VEX sync');
    }
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  }

  function formatNumber(num: number) {
    return num.toLocaleString();
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading data source status...</div>;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
        </div>
      )}

      {/* NVD Status */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Database className="w-6 h-6 text-[#4ade80]" />
            <div>
              <h2 className="text-lg font-semibold text-[#e8f5e9]">NVD (National Vulnerability Database)</h2>
              <p className="text-sm text-[#6b7280]">CVE details, CVSS scores, and CWE information</p>
            </div>
          </div>
          <button
            onClick={handleNVDSync}
            disabled={nvdStatus?.syncing}
            className="btn btn-primary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${nvdStatus?.syncing ? 'animate-spin' : ''}`} />
            {nvdStatus?.syncing ? 'Syncing...' : 'Sync Now'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="text-2xl font-bold text-[#e8f5e9]">
              {formatNumber(nvdStatus?.cveCount || 0)}
            </div>
            <div className="text-sm text-[#6b7280]">CVEs in database</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="flex items-center gap-2">
              {nvdStatus?.syncing ? (
                <Clock className="w-5 h-5 text-yellow-400" />
              ) : nvdStatus?.lastSync ? (
                <CheckCircle2 className="w-5 h-5 text-[#4ade80]" />
              ) : (
                <AlertCircle className="w-5 h-5 text-[#6b7280]" />
              )}
              <span className="text-[#e8f5e9]">
                {nvdStatus?.syncing ? 'Syncing...' : formatDate(nvdStatus?.lastSync || null)}
              </span>
            </div>
            <div className="text-sm text-[#6b7280]">Last sync</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="flex items-center gap-2">
              {nvdStatus?.hasApiKey ? (
                <CheckCircle2 className="w-5 h-5 text-[#4ade80]" />
              ) : (
                <AlertCircle className="w-5 h-5 text-yellow-400" />
              )}
              <span className="text-[#e8f5e9]">
                {nvdStatus?.hasApiKey ? 'API Key configured' : 'No API Key'}
              </span>
            </div>
            <div className="text-sm text-[#6b7280]">
              {nvdStatus?.hasApiKey ? 'Higher rate limits' : 'Limited to 5 req/30s'}
            </div>
          </div>
        </div>
      </div>

      {/* ExploitDB Status */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-red-400" />
            <div>
              <h2 className="text-lg font-semibold text-[#e8f5e9]">ExploitDB</h2>
              <p className="text-sm text-[#6b7280]">Public exploits and PoC code database</p>
            </div>
          </div>
          <button
            onClick={handleExploitDBSync}
            disabled={exploitStatus?.syncing}
            className="btn btn-primary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${exploitStatus?.syncing ? 'animate-spin' : ''}`} />
            {exploitStatus?.syncing ? 'Syncing...' : 'Sync Now'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="text-2xl font-bold text-[#e8f5e9]">
              {formatNumber(exploitStatus?.exploitCount || 0)}
            </div>
            <div className="text-sm text-[#6b7280]">Exploits in database</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="flex items-center gap-2">
              {exploitStatus?.syncing ? (
                <Clock className="w-5 h-5 text-yellow-400" />
              ) : exploitStatus?.lastSync ? (
                <CheckCircle2 className="w-5 h-5 text-[#4ade80]" />
              ) : (
                <AlertCircle className="w-5 h-5 text-[#6b7280]" />
              )}
              <span className="text-[#e8f5e9]">
                {exploitStatus?.syncing ? 'Syncing...' : formatDate(exploitStatus?.lastSync || null)}
              </span>
            </div>
            <div className="text-sm text-[#6b7280]">Last sync</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="text-2xl font-bold text-[#e8f5e9]">
              {formatNumber(exploitStatus?.exploitsWithCve || 0)}
            </div>
            <div className="text-sm text-[#6b7280]">With CVE links</div>
          </div>
        </div>
      </div>

      {/* VEX Status */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-sky-400" />
            <div>
              <h2 className="text-lg font-semibold text-[#e8f5e9]">Ubuntu VEX</h2>
              <p className="text-sm text-[#6b7280]">Canonical VEX statements — marks packages as not affected, under investigation, or won't fix</p>
            </div>
          </div>
          <button
            onClick={handleVEXSync}
            disabled={vexStatus?.syncing}
            className="btn btn-primary flex items-center gap-2"
          >
            <RefreshCw className={`w-4 h-4 ${vexStatus?.syncing ? 'animate-spin' : ''}`} />
            {vexStatus?.syncing ? 'Syncing...' : 'Sync Now'}
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="text-2xl font-bold text-[#e8f5e9]">
              {formatNumber(vexStatus?.statementCount || 0)}
            </div>
            <div className="text-sm text-[#6b7280]">VEX statements</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="flex items-center gap-2">
              {vexStatus?.syncing ? (
                <Clock className="w-5 h-5 text-yellow-400" />
              ) : vexStatus?.lastSync ? (
                <CheckCircle2 className="w-5 h-5 text-[#4ade80]" />
              ) : (
                <AlertCircle className="w-5 h-5 text-[#6b7280]" />
              )}
              <span className="text-[#e8f5e9]">
                {vexStatus?.syncing ? 'Syncing...' : formatDate(vexStatus?.lastSync || null)}
              </span>
            </div>
            <div className="text-sm text-[#6b7280]">Last sync</div>
          </div>
          <div className="bg-[#1a2420] rounded-lg p-4">
            <div className="flex items-center gap-2">
              {vexStatus?.status === 'success' ? (
                <CheckCircle2 className="w-5 h-5 text-[#4ade80]" />
              ) : vexStatus?.status === 'failed' ? (
                <AlertCircle className="w-5 h-5 text-red-400" />
              ) : vexStatus?.status === 'syncing' ? (
                <Clock className="w-5 h-5 text-yellow-400" />
              ) : (
                <AlertCircle className="w-5 h-5 text-[#6b7280]" />
              )}
              <span className="text-[#e8f5e9] capitalize">
                {vexStatus?.status || 'Never synced'}
              </span>
            </div>
            <div className="text-sm text-[#6b7280]">Sync status</div>
          </div>
        </div>
        {vexStatus?.error && (
          <div className="mt-3 p-2 bg-red-600/10 border border-red-600/30 rounded text-sm text-red-400">
            {vexStatus.error}
          </div>
        )}
      </div>

      {/* Configuration */}
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Settings className="w-6 h-6 text-[#4ade80]" />
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Configuration</h2>
        </div>

        {success && (
          <div className="p-3 mb-4 bg-[#4ade80]/10 border border-[#4ade80]/50 rounded-lg text-[#4ade80]">
            {success}
          </div>
        )}

        <div className="space-y-4">
          {/* NVD API Key */}
          <div>
            <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
              NVD API Key
            </label>
            <p className="text-xs text-[#6b7280] mb-2">
              Optional. Get a free API key from{' '}
              <a 
                href="https://nvd.nist.gov/developers/request-an-api-key" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-[#4ade80] hover:underline"
              >
                nvd.nist.gov
              </a>
              {' '}to increase rate limits from 5 to 50 requests per 30 seconds.
            </p>
            <div className="flex gap-2">
              <input
                type={showApiKey ? 'text' : 'password'}
                value={config.nvd_api_key}
                onChange={(e) => setConfig({ ...config, nvd_api_key: e.target.value })}
                placeholder="Enter NVD API key..."
                className="input flex-1"
              />
              <button
                type="button"
                onClick={() => setShowApiKey(!showApiKey)}
                className="btn btn-secondary px-3"
              >
                {showApiKey ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          {/* Sync Intervals */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                NVD Sync Interval (hours)
              </label>
              <p className="text-xs text-[#6b7280] mb-2">
                How often to check for new CVEs. Default: 6 hours.
              </p>
              <input
                type="number"
                min="1"
                max="168"
                value={config.nvd_sync_interval_hours}
                onChange={(e) => setConfig({ ...config, nvd_sync_interval_hours: e.target.value })}
                className="input w-full"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                ExploitDB Sync Interval (hours)
              </label>
              <p className="text-xs text-[#6b7280] mb-2">
                How often to check for new exploits. Default: 24 hours.
              </p>
              <input
                type="number"
                min="1"
                max="168"
                value={config.exploitdb_sync_interval_hours}
                onChange={(e) => setConfig({ ...config, exploitdb_sync_interval_hours: e.target.value })}
                className="input w-full"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#a5d6a7] mb-1">
                VEX Sync Interval (hours)
              </label>
              <p className="text-xs text-[#6b7280] mb-2">
                How often to sync Ubuntu VEX data. Default: 24 hours.
              </p>
              <input
                type="number"
                min="1"
                max="168"
                value={config.vex_sync_interval_hours}
                onChange={(e) => setConfig({ ...config, vex_sync_interval_hours: e.target.value })}
                className="input w-full"
              />
            </div>
          </div>

          {/* Save Button */}
          <div className="pt-2">
            <button
              onClick={handleSaveConfig}
              disabled={saving}
              className="btn btn-primary flex items-center gap-2"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving...' : 'Save Configuration'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Agents Tab
// ============================================================================

type AgentSortField = 'hostname' | 'lastIp' | 'status' | 'agentVersion' | 'lastSeenAt' | 'createdAt';
type SortDirection = 'asc' | 'desc';

function AgentsTab() {
  const [agents, setAgents] = useState<RegisteredAgent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; agent: RegisteredAgent | null }>({ isOpen: false, agent: null });
  
  // Search, sort, pagination state
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<AgentSortField>('hostname');
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  useEffect(() => {
    fetchAgents();
  }, []);

  // Reset to first page when search changes
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  async function fetchAgents() {
    try {
      const data = await getRegisteredAgents();
      setAgents(data.agents || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  }

  async function handleApprove(id: number) {
    try {
      await approveAgent(id);
      fetchAgents();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to approve agent');
    }
  }

  async function handleRevoke(id: number) {
    try {
      await revokeAgent(id);
      fetchAgents();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke agent');
    }
  }

  function openDeleteModal(agent: RegisteredAgent) {
    setDeleteModal({ isOpen: true, agent });
  }

  async function confirmDelete() {
    if (!deleteModal.agent) return;
    const agentId = deleteModal.agent.id;
    setDeleteModal({ isOpen: false, agent: null });
    try {
      await deleteAgent(agentId);
      fetchAgents();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete agent');
    }
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'active':
        return <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">Active</span>;
      case 'pending':
        return <span className="px-2 py-1 rounded text-xs font-medium bg-yellow-600/20 text-yellow-400">Pending</span>;
      case 'revoked':
        return <span className="px-2 py-1 rounded text-xs font-medium bg-red-600/20 text-red-400">Revoked</span>;
      default:
        return <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600/20 text-gray-400">{status}</span>;
    }
  }

  function handleSort(field: AgentSortField) {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  }

  function SortIcon({ field }: { field: AgentSortField }) {
    if (sortField !== field) {
      return <ChevronUp className="w-4 h-4 opacity-30" />;
    }
    return sortDirection === 'asc' 
      ? <ChevronUp className="w-4 h-4" /> 
      : <ChevronDown className="w-4 h-4" />;
  }

  // Filter agents by search query
  const filteredAgents = agents.filter(agent => {
    if (!searchQuery) return true;
    const query = searchQuery.toLowerCase();
    return (
      agent.hostname.toLowerCase().includes(query) ||
      agent.status.toLowerCase().includes(query) ||
      (agent.lastIp && agent.lastIp.toLowerCase().includes(query))
    );
  });

  // Sort agents
  const sortedAgents = [...filteredAgents].sort((a, b) => {
    let aVal: string | number = '';
    let bVal: string | number = '';
    
    switch (sortField) {
      case 'hostname':
        aVal = a.hostname.toLowerCase();
        bVal = b.hostname.toLowerCase();
        break;
      case 'lastIp':
        aVal = a.lastIp?.toLowerCase() || '';
        bVal = b.lastIp?.toLowerCase() || '';
        break;
      case 'status':
        // Sort order: pending, active, revoked
        const statusOrder: Record<string, number> = { pending: 0, active: 1, revoked: 2 };
        aVal = statusOrder[a.status] ?? 3;
        bVal = statusOrder[b.status] ?? 3;
        break;
      case 'agentVersion':
        aVal = a.agentVersion?.toLowerCase() || '';
        bVal = b.agentVersion?.toLowerCase() || '';
        break;
      case 'lastSeenAt':
        aVal = a.lastSeenAt ? new Date(a.lastSeenAt).getTime() : 0;
        bVal = b.lastSeenAt ? new Date(b.lastSeenAt).getTime() : 0;
        break;
      case 'createdAt':
        aVal = a.createdAt ? new Date(a.createdAt).getTime() : 0;
        bVal = b.createdAt ? new Date(b.createdAt).getTime() : 0;
        break;
    }
    
    if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
    if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  // Pagination
  const totalPages = Math.ceil(sortedAgents.length / itemsPerPage);
  const paginatedAgents = sortedAgents.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  const pendingAgents = agents.filter(a => a.status === 'pending');

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading agents...</div>;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
        </div>
      )}

      {/* Pending Approval */}
      {pendingAgents.length > 0 && (
        <div className="card border-yellow-600/50">
          <h2 className="text-lg font-semibold text-yellow-400 mb-4 flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Pending Approval ({pendingAgents.length})
          </h2>
          <div className="space-y-2">
            {pendingAgents.map((agent) => (
              <div key={agent.id} className="flex items-center justify-between bg-[#1a2420] rounded-lg p-3">
                <div>
                  <div className="text-[#e8f5e9] font-medium">{agent.hostname}</div>
                  <div className="text-xs text-[#6b7280]">
                    Enrolled {formatDate(agent.createdAt)}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button
                    onClick={() => handleApprove(agent.id)}
                    className="btn btn-primary text-sm py-1"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => openDeleteModal(agent)}
                    className="btn btn-secondary text-sm py-1"
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All Agents Table */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">
            Registered Agents ({agents.length})
          </h2>
          
          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#6b7280] pointer-events-none" />
            <input
              type="text"
              placeholder="Search agents..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input !pl-10 w-64"
            />
          </div>
        </div>

        {agents.length === 0 ? (
          <p className="text-[#6b7280]">No agents registered yet.</p>
        ) : filteredAgents.length === 0 ? (
          <p className="text-[#6b7280]">No agents match your search.</p>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#2d3f36]">
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('hostname')}
                    >
                      <div className="flex items-center gap-1">
                        Hostname
                        <SortIcon field="hostname" />
                      </div>
                    </th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('lastIp')}
                    >
                      <div className="flex items-center gap-1">
                        IP Address
                        <SortIcon field="lastIp" />
                      </div>
                    </th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('status')}
                    >
                      <div className="flex items-center gap-1">
                        Status
                        <SortIcon field="status" />
                      </div>
                    </th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('agentVersion')}
                    >
                      <div className="flex items-center gap-1">
                        Version
                        <SortIcon field="agentVersion" />
                      </div>
                    </th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('lastSeenAt')}
                    >
                      <div className="flex items-center gap-1">
                        Last Seen
                        <SortIcon field="lastSeenAt" />
                      </div>
                    </th>
                    <th 
                      className="table-header text-left py-3 px-4 cursor-pointer hover:text-[#4ade80] select-none"
                      onClick={() => handleSort('createdAt')}
                    >
                      <div className="flex items-center gap-1">
                        Enrolled
                        <SortIcon field="createdAt" />
                      </div>
                    </th>
                    <th className="table-header text-right py-3 px-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAgents.map((agent) => {
                    const hasAuthFailure = !!agent.lastAuthFailureAt &&
                      (Date.now() - new Date(agent.lastAuthFailureAt).getTime()) < 24 * 60 * 60 * 1000;
                    const authFailureTooltip = hasAuthFailure
                      ? `Auth failure from ${agent.authFailureIp || 'unknown IP'} at ${new Date(agent.lastAuthFailureAt!).toLocaleString()}`
                      : '';
                    return (
                    <tr key={agent.id} className="table-row">
                      <td className="py-3 px-4 text-[#e8f5e9] font-medium">
                        <div className="flex items-center gap-2">
                          {agent.hostname}
                          {hasAuthFailure && (
                            <span title={authFailureTooltip}>
                              <AlertCircle className="w-4 h-4 text-yellow-400 flex-shrink-0" />
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-[#6b7280] font-mono text-sm">{agent.lastIp || '-'}</td>
                      <td className="py-3 px-4">{getStatusBadge(agent.status)}</td>
                      <td className="py-3 px-4 text-[#6b7280] font-mono text-sm">{agent.agentVersion || '-'}</td>
                      <td className="py-3 px-4 text-[#6b7280] text-sm">{formatDate(agent.lastSeenAt)}</td>
                      <td className="py-3 px-4 text-[#6b7280] text-sm">{formatDate(agent.createdAt)}</td>
                      <td className="py-3 px-4 text-right">
                        {agent.status === 'pending' && (
                          <button
                            onClick={() => handleApprove(agent.id)}
                            className="p-1 text-[#4ade80] hover:text-[#22c55e]"
                            title="Approve"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                        )}
                        {agent.status === 'active' && (
                          <button
                            onClick={() => handleRevoke(agent.id)}
                            className="p-1 text-yellow-400 hover:text-yellow-300"
                            title="Revoke"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        )}
                        <button
                          onClick={() => openDeleteModal(agent)}
                          className="p-1 text-[#6b7280] hover:text-red-400 ml-2"
                          title="Delete"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2d3f36]">
                <div className="text-sm text-[#6b7280]">
                  Showing {(currentPage - 1) * itemsPerPage + 1} to {Math.min(currentPage * itemsPerPage, sortedAgents.length)} of {sortedAgents.length} agents
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    className="p-2 rounded hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed text-[#a5d6a7]"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let pageNum: number;
                    if (totalPages <= 5) {
                      pageNum = i + 1;
                    } else if (currentPage <= 3) {
                      pageNum = i + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + i;
                    } else {
                      pageNum = currentPage - 2 + i;
                    }
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setCurrentPage(pageNum)}
                        className={`w-8 h-8 rounded text-sm ${
                          currentPage === pageNum
                            ? 'bg-[#4ade80] text-[#0d1512] font-medium'
                            : 'hover:bg-[#2d3f36] text-[#a5d6a7]'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                  
                  <button
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    className="p-2 rounded hover:bg-[#2d3f36] disabled:opacity-50 disabled:cursor-not-allowed text-[#a5d6a7]"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Agent"
        message={deleteModal.agent 
          ? `Are you sure you want to delete the agent "${deleteModal.agent.hostname}"? This cannot be undone.`
          : ''
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setDeleteModal({ isOpen: false, agent: null })}
      />
    </div>
  );
}

// ============================================================================
// Enrollment Keys Tab
// ============================================================================

function EnrollmentKeysTab() {
  const [keys, setKeys] = useState<EnrollmentKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showNewForm, setShowNewForm] = useState(false);
  const [newForm, setNewForm] = useState({ name: '', maxUses: '', autoApprove: false });
  const [newKeyResult, setNewKeyResult] = useState<{ key: EnrollmentKey; fullKey: string } | null>(null);
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; key: EnrollmentKey | null }>({ isOpen: false, key: null });

  useEffect(() => {
    fetchKeys();
  }, []);

  async function fetchKeys() {
    try {
      const data = await getEnrollmentKeys();
      setKeys(data.keys || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load keys');
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate() {
    try {
      const result = await createEnrollmentKey({
        name: newForm.name,
        maxUses: newForm.maxUses ? parseInt(newForm.maxUses) : undefined,
        autoApprove: newForm.autoApprove,
      });
      setNewKeyResult(result);
      setShowNewForm(false);
      setNewForm({ name: '', maxUses: '', autoApprove: false });
      fetchKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create key');
    }
  }

  function openDeleteModal(key: EnrollmentKey) {
    setDeleteModal({ isOpen: true, key });
  }

  async function confirmDelete() {
    if (!deleteModal.key) return;
    const keyId = deleteModal.key.id;
    setDeleteModal({ isOpen: false, key: null });
    try {
      await deleteEnrollmentKey(keyId);
      fetchKeys();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete key');
    }
  }

  function formatDate(dateStr: string | null) {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  }

  if (loading) {
    return <div className="text-[#a5d6a7]">Loading enrollment keys...</div>;
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
          <button onClick={() => setError(null)} className="ml-2 underline">Dismiss</button>
        </div>
      )}

      {/* New Key Result */}
      {newKeyResult && (
        <div className="card border-green-600/50 bg-green-600/5">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="w-6 h-6 text-green-400 mt-1" />
            <div className="flex-1">
              <h3 className="font-semibold text-green-400">Enrollment Key Created</h3>
              <p className="text-sm text-[#a5d6a7] mt-1">
                Copy this key now - it will only be shown once!
              </p>
              <div className="mt-3 p-3 bg-[#0a0f0d] rounded-lg font-mono text-sm text-[#e8f5e9] break-all">
                {newKeyResult.fullKey}
              </div>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(newKeyResult.fullKey);
                }}
                className="btn btn-secondary mt-3 text-sm"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={() => setNewKeyResult(null)}
                className="btn btn-secondary mt-3 ml-2 text-sm"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-[#e8f5e9]">Enrollment Keys</h2>
          <button
            onClick={() => setShowNewForm(true)}
            className="btn btn-primary flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Create Key
          </button>
        </div>

        <p className="text-sm text-[#6b7280] mb-4">
          Agents use enrollment keys to register with VulTrack. Create keys for different teams or environments.
        </p>

        {/* New Key Form */}
        {showNewForm && (
          <div className="mb-4 p-4 bg-[#1a2420] border border-[#2d3f36] rounded-lg">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Name</label>
                <input
                  type="text"
                  value={newForm.name}
                  onChange={(e) => setNewForm({ ...newForm, name: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                  placeholder="e.g., Production Servers"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-[#a5d6a7] mb-1">Max Uses (optional)</label>
                <input
                  type="number"
                  value={newForm.maxUses}
                  onChange={(e) => setNewForm({ ...newForm, maxUses: e.target.value })}
                  className="w-full px-3 py-2 bg-[#0a0f0d] border border-[#2d3f36] rounded-lg text-[#e8f5e9] focus:outline-none focus:border-[#4ade80]"
                  placeholder="Unlimited"
                  min="1"
                />
              </div>
            </div>
            
            {/* Auto-Approve Toggle */}
            <div className="mt-4">
              <label className="flex items-center gap-3 cursor-pointer">
                <div className="relative">
                  <input
                    type="checkbox"
                    checked={newForm.autoApprove}
                    onChange={(e) => setNewForm({ ...newForm, autoApprove: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-10 h-6 bg-[#2d3f36] rounded-full peer peer-checked:bg-[#4ade80] transition-colors"></div>
                  <div className="absolute left-1 top-1 w-4 h-4 bg-[#6b7280] rounded-full peer-checked:translate-x-4 peer-checked:bg-white transition-all"></div>
                </div>
                <div>
                  <span className="text-sm font-medium text-[#e8f5e9]">Auto-approve agents</span>
                  <p className="text-xs text-[#6b7280]">
                    When enabled, agents using this key will be automatically approved without manual review.
                  </p>
                </div>
              </label>
            </div>

            <div className="flex justify-end gap-2 mt-4">
              <button onClick={() => setShowNewForm(false)} className="btn btn-secondary">
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={!newForm.name.trim()}
                className="btn btn-primary"
              >
                Create
              </button>
            </div>
          </div>
        )}

        {/* Keys Table */}
        {keys.length === 0 ? (
          <p className="text-[#6b7280]">No enrollment keys created yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#2d3f36]">
                  <th className="table-header text-left py-3 px-4">Name</th>
                  <th className="table-header text-left py-3 px-4">Key Prefix</th>
                  <th className="table-header text-left py-3 px-4">Status</th>
                  <th className="table-header text-left py-3 px-4">Auto-Approve</th>
                  <th className="table-header text-left py-3 px-4">Usage</th>
                  <th className="table-header text-left py-3 px-4">Created</th>
                  <th className="table-header text-right py-3 px-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((key) => (
                  <tr key={key.id} className="table-row">
                    <td className="py-3 px-4 text-[#e8f5e9] font-medium">{key.name}</td>
                    <td className="py-3 px-4 font-mono text-sm text-[#6b7280]">{key.keyPrefix}...</td>
                    <td className="py-3 px-4">
                      {key.isActive ? (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-green-600/20 text-green-400">Active</span>
                      ) : (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600/20 text-gray-400">Inactive</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {key.autoApprove ? (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-blue-600/20 text-blue-400">Yes</span>
                      ) : (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-gray-600/20 text-gray-400">No</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-[#a5d6a7]">
                      {key.usedCount}{key.maxUses ? ` / ${key.maxUses}` : ' / ∞'}
                    </td>
                    <td className="py-3 px-4 text-[#6b7280] text-sm">{formatDate(key.createdAt)}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => openDeleteModal(key)}
                        className="p-1 text-[#6b7280] hover:text-red-400"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Enrollment Key"
        message={deleteModal.key 
          ? `Are you sure you want to delete the enrollment key "${deleteModal.key.name}"? Agents registered with this key will continue to work.`
          : ''
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={() => setDeleteModal({ isOpen: false, key: null })}
      />
    </div>
  );
}

// Server Management Tab
function ServerManagementTab() {
  const [servers, setServers] = useState<ServerType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; server: ServerType | null }>({ isOpen: false, server: null });
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  async function fetchData() {
    setLoading(true);
    setError(null);
    try {
      const data = await getServers();
      setServers(data.servers || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load servers');
    } finally {
      setLoading(false);
    }
  }

  function openDeleteModal(server: ServerType) {
    setDeleteModal({ isOpen: true, server });
  }

  function closeDeleteModal() {
    setDeleteModal({ isOpen: false, server: null });
  }

  async function confirmDelete() {
    if (!deleteModal.server) return;
    
    setDeleting(true);
    try {
      await deleteServer(deleteModal.server.id);
      closeDeleteModal();
      fetchData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete server');
      setDeleting(false);
    }
  }

  // Fuzzy search filter
  const filteredServers = searchQuery.trim()
    ? servers.filter(s => {
        const query = searchQuery.toLowerCase();
        return (
          s.name.toLowerCase().includes(query) ||
          s.osFamily?.toLowerCase().includes(query) ||
          s.osRelease?.toLowerCase().includes(query) ||
          s.kernel?.toLowerCase().includes(query) ||
          s.ipv4Addrs?.some(ip => ip.toLowerCase().includes(query))
        );
      })
    : servers;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#a5d6a7]">Loading servers...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-[#e8f5e9] flex items-center gap-2">
            <Server className="w-5 h-5 text-[#4ade80]" />
            Server Management
          </h2>
          <p className="text-sm text-[#a5d6a7] mt-1">
            Delete servers and all their associated data (findings, packages, etc.)
          </p>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 bg-red-600/10 border border-red-600/50 rounded-lg text-red-400">
          {error}
        </div>
      )}

      {/* Search */}
      <div className="card">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-[#6b7280]" />
          <input
            type="text"
            placeholder="Search servers by name, OS, kernel, or IP address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-[#0d1512] border border-[#2d3f36] rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-[#4ade80]"
          />
        </div>
        <div className="mt-3 text-sm text-[#a5d6a7]">
          {filteredServers.length} of {servers.length} servers
        </div>
      </div>

      {/* Server List */}
      <div className="card">
        <div className="space-y-2">
          {filteredServers.length === 0 ? (
            <div className="text-center py-8 text-[#6b7280]">
              {searchQuery.trim() ? 'No servers found matching your search' : 'No servers found'}
            </div>
          ) : (
            filteredServers.map((server) => (
              <div
                key={server.id}
                className="flex items-center justify-between p-4 bg-[#0d1512] border border-[#2d3f36] rounded-lg hover:border-[#4ade80]/30 transition-colors"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="text-[#e8f5e9] font-medium truncate">{server.name}</div>
                      <div className="flex items-center gap-4 mt-1 text-sm text-[#6b7280]">
                        {server.osFamily && (
                          <span>{server.osFamily} {server.osRelease}</span>
                        )}
                        {server.kernel && (
                          <span>Kernel: {server.kernel}</span>
                        )}
                        {server.findingsCount !== undefined && (
                          <span className="text-[#a5d6a7]">
                            {server.findingsCount} findings
                            {server.criticalCount !== undefined && server.criticalCount > 0 && (
                              <span className="text-red-400 ml-1">
                                ({server.criticalCount} critical)
                              </span>
                            )}
                          </span>
                        )}
                      </div>
                      {server.ipv4Addrs && server.ipv4Addrs.length > 0 && (
                        <div className="mt-1 text-xs text-[#6b7280]">
                          IPs: {server.ipv4Addrs.join(', ')}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => openDeleteModal(server)}
                  className="ml-4 p-2 text-red-400 hover:text-red-300 hover:bg-red-600/10 rounded-lg transition-colors"
                  title="Delete server"
                >
                  <Trash2 className="w-5 h-5" />
                </button>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Warning Info */}
      <div className="card bg-yellow-600/5 border-yellow-600/30">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-400 mt-0.5" />
          <div className="flex-1">
            <h3 className="text-[#e8f5e9] font-semibold mb-1">Warning</h3>
            <p className="text-sm text-[#a5d6a7]">
              Deleting a server will permanently remove:
            </p>
            <ul className="mt-2 text-sm text-[#a5d6a7] list-disc list-inside space-y-1">
              <li>All findings associated with this server</li>
              <li>All package information for this server</li>
              <li>All server group memberships</li>
              <li>The server record itself</li>
            </ul>
            <p className="mt-2 text-sm text-[#a5d6a7]">
              Registered agents linked to this server will be unlinked (but not deleted).
            </p>
          </div>
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        title="Delete Server"
        message={
          deleteModal.server
            ? `Are you sure you want to delete "${deleteModal.server.name}"? This will permanently delete all findings, packages, and other data associated with this server. This action cannot be undone.`
            : ''
        }
        confirmLabel={deleting ? 'Deleting...' : 'Delete Server'}
        cancelLabel="Cancel"
        variant="danger"
        onConfirm={confirmDelete}
        onCancel={closeDeleteModal}
      />
    </div>
  );
}

// Users Tab (OIDC user management)
function UsersTab() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updatingId, setUpdatingId] = useState<number | null>(null);

  const loadUsers = useCallback(async () => {
    setError(null);
    try {
      const data = await getAdminUsers();
      setUsers(data.users ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  async function handleToggleAdmin(user: AdminUser) {
    setUpdatingId(user.id);
    setError(null);
    try {
      const updated = await updateUserAdmin(user.id, !user.isAdmin);
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    } finally {
      setUpdatingId(null);
    }
  }

  if (loading) {
    return (
      <div className="card">
        <div className="flex items-center gap-3 mb-4">
          <Users className="w-6 h-6 text-[#4ade80]" />
          <h2 className="text-lg font-semibold text-[#e8f5e9]">User Management</h2>
        </div>
        <p className="text-[#a5d6a7]">Loading users...</p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="flex items-center gap-3 mb-4">
        <Users className="w-6 h-6 text-[#4ade80]" />
        <h2 className="text-lg font-semibold text-[#e8f5e9]">User Management</h2>
      </div>
      <p className="text-sm text-[#6b7280] mb-4">
        Users are created when they sign in via OIDC. Grant or revoke admin access below.
      </p>
      {error && (
        <div className="mb-4 p-3 rounded-lg bg-red-500/10 text-red-400 text-sm">{error}</div>
      )}
      {users.length === 0 ? (
        <p className="text-[#a5d6a7]">No users yet. Users appear after they sign in with OIDC.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#2d3f36] text-left text-[#6b7280]">
                <th className="py-3 px-2">Email</th>
                <th className="py-3 px-2">Name</th>
                <th className="py-3 px-2">Admin</th>
                <th className="py-3 px-2">Last login</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b border-[#2d3f36]">
                  <td className="py-3 px-2 text-[#e8f5e9]">{u.email}</td>
                  <td className="py-3 px-2 text-[#a5d6a7]">{u.name || '—'}</td>
                  <td className="py-3 px-2">
                    <button
                      type="button"
                      disabled={updatingId === u.id}
                      onClick={() => handleToggleAdmin(u)}
                      className={`px-3 py-1 rounded text-xs font-medium ${
                        u.isAdmin
                          ? 'bg-[#4ade80]/20 text-[#4ade80] hover:bg-[#4ade80]/30'
                          : 'bg-[#2d3f36] text-[#6b7280] hover:bg-[#1a2420] hover:text-[#a5d6a7]'
                      }`}
                    >
                      {updatingId === u.id ? '…' : u.isAdmin ? 'Revoke admin' : 'Grant admin'}
                    </button>
                  </td>
                  <td className="py-3 px-2 text-[#6b7280]">
                    {u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// System Reset Tab
function ResetTab() {
  const [showConfirmModal, setShowConfirmModal] = useState(false);
  const [resetMode, setResetMode] = useState<'full' | 'findings_only' | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const [resetting, setResetting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    resetType?: string;
    message?: string;
    serversDeleted?: number;
    findingsDeleted?: number;
    assessmentsDeleted?: number;
    serverGroupsDeleted?: number;
    agentsDeleted?: number;
    enrollmentKeysDeleted?: number;
  } | null>(null);

  const isFindingsOnly = resetMode === 'findings_only';
  const confirmPhrase = isFindingsOnly ? 'DELETE FINDINGS' : 'RESET VULTRACK';
  const confirmValid = confirmText === confirmPhrase;

  const openModal = (mode: 'full' | 'findings_only') => {
    setResetMode(mode);
    setConfirmText('');
    setError(null);
    setShowConfirmModal(true);
  };

  const closeModal = () => {
    setShowConfirmModal(false);
    setResetMode(null);
    setConfirmText('');
    setError(null);
  };

  const handleReset = async () => {
    if (!confirmValid) {
      setError(`Please type "${confirmPhrase}" to confirm.`);
      return;
    }

    setResetting(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/admin/system/reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          confirm: confirmText,
          resetType: isFindingsOnly ? 'findings_only' : 'full',
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Reset failed');
      }

      setResult(data);
      closeModal();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Reset failed');
    } finally {
      setResetting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Success Result */}
      {result && (
        <div className="bg-green-900/30 border border-green-600 rounded-xl p-6">
          <h3 className="text-xl font-bold text-green-400 mb-4 flex items-center gap-2">
            <CheckCircle2 className="w-6 h-6" />
            {result.resetType === 'findings_only' ? 'Findings deleted successfully' : 'Reset completed successfully'}
          </h3>
          {result.resetType === 'findings_only' ? (
            <div className="text-[#e8f5e9]">
              <div className="bg-[#1a2420] rounded-lg p-3 inline-block">
                <div className="text-2xl font-bold text-red-400">{result.findingsDeleted ?? 0}</div>
                <div className="text-sm text-[#a5d6a7]">Findings deleted</div>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-[#e8f5e9]">
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.serversDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Servers deleted</div>
              </div>
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.findingsDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Findings deleted</div>
              </div>
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.assessmentsDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Assessments deleted</div>
              </div>
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.serverGroupsDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Groups deleted</div>
              </div>
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.agentsDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Agents deleted</div>
              </div>
              <div className="bg-[#1a2420] rounded-lg p-3">
                <div className="text-2xl font-bold text-red-400">{result.enrollmentKeysDeleted}</div>
                <div className="text-sm text-[#a5d6a7]">Keys deleted</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reset options – two independent actions side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-6">
        {/* Left column: Delete findings only */}
        <div className="space-y-4">
          <div className="card border-amber-600/50">
            <h3 className="text-lg font-bold text-amber-400 mb-3 flex items-center gap-2">
              <Trash2 className="w-5 h-5" />
              What will be deleted?
            </h3>
            <ul className="space-y-2 text-[#e8f5e9] text-sm">
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-amber-500 flex-shrink-0" />
                <span><strong>All Findings</strong> – All detected vulnerabilities will be removed</span>
              </li>
            </ul>
          </div>
          <div className="card border-green-600/50">
            <h3 className="text-lg font-bold text-green-400 mb-3 flex items-center gap-2">
              <Check className="w-5 h-5" />
              What will be preserved?
            </h3>
            <ul className="space-y-2 text-[#e8f5e9] text-sm">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <span><strong>Servers</strong>, <strong>Packages</strong>, <strong>Assessments</strong>, <strong>Groups</strong>, <strong>Agents</strong>, <strong>Enrollment Keys</strong></span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <span><strong>OVAL</strong>, <strong>NVD</strong>, <strong>ExploitDB</strong>, <strong>Settings</strong>, <strong>Users</strong></span>
              </li>
            </ul>
          </div>
          <div className="card border-amber-600/50 flex flex-col">
            <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Delete findings only</h3>
            <p className="text-[#a5d6a7] text-sm mb-4">
              Use this to ensure only new scan results appear after the next agent report.
            </p>
            <button
              onClick={() => openModal('findings_only')}
              className="w-full py-3 px-5 bg-amber-600 hover:bg-amber-700 text-white font-medium rounded-xl flex items-center justify-center gap-2 transition-colors mt-auto"
            >
              <Trash2 className="w-5 h-5" />
              Delete findings only
            </button>
          </div>
        </div>

        {/* Right column: Full reset */}
        <div className="space-y-4">
          <div className="card border-red-600/50">
            <h3 className="text-lg font-bold text-red-400 mb-3 flex items-center gap-2">
              <Trash2 className="w-5 h-5" />
              What will be deleted?
            </h3>
            <ul className="space-y-2 text-[#e8f5e9] text-sm">
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-red-500 flex-shrink-0" />
                <span><strong>All Servers</strong> – All registered servers will be removed</span>
              </li>
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-red-500 flex-shrink-0" />
                <span><strong>All Findings</strong> – All detected vulnerabilities will be deleted</span>
              </li>
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-red-500 flex-shrink-0" />
                <span><strong>All Package Data</strong> – Installed packages from all servers</span>
              </li>
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-red-500 flex-shrink-0" />
                <span><strong>All Assessments</strong> – All CVE assessments</span>
              </li>
              <li className="flex items-center gap-2">
                <X className="w-4 h-4 text-red-500 flex-shrink-0" />
                <span><strong>All Server Groups</strong>, <strong>Agents</strong>, <strong>Enrollment Keys</strong></span>
              </li>
            </ul>
          </div>
          <div className="card border-green-600/50">
            <h3 className="text-lg font-bold text-green-400 mb-3 flex items-center gap-2">
              <Check className="w-5 h-5" />
              What will be preserved?
            </h3>
            <ul className="space-y-2 text-[#e8f5e9] text-sm">
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <span><strong>OVAL</strong>, <strong>NVD</strong>, <strong>ExploitDB</strong> – Vulnerability data sources</span>
              </li>
              <li className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0" />
                <span><strong>Settings</strong>, <strong>Reason Templates</strong>, <strong>Users</strong></span>
              </li>
            </ul>
          </div>
          <div className="card border-red-600/50 flex flex-col">
            <h3 className="text-lg font-semibold text-[#e8f5e9] mb-2">Reset VulTrack (full)</h3>
            <p className="text-[#a5d6a7] text-sm mb-4">
              This action <strong>cannot be undone</strong>. All operational data will be permanently deleted.
            </p>
            <button
              onClick={() => openModal('full')}
              className="w-full py-3 px-5 bg-red-600 hover:bg-red-700 text-white font-bold rounded-xl flex items-center justify-center gap-2 transition-colors mt-auto"
            >
              <RotateCcw className="w-5 h-5" />
              Reset VulTrack
            </button>
          </div>
        </div>
      </div>

      {/* Confirmation Modal */}
      {showConfirmModal && resetMode !== null && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
          <div className="bg-[#111916] border-2 border-red-600 rounded-xl p-6 w-full max-w-lg">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-8 h-8 text-red-500" />
              <h2 className="text-xl font-bold text-red-400">
                {isFindingsOnly ? 'Delete all findings?' : 'Final Confirmation Required'}
              </h2>
            </div>

            <div className="bg-red-900/30 border border-red-600/50 rounded-lg p-4 mb-6">
              <p className="text-red-300 font-medium">
                {isFindingsOnly
                  ? 'All findings will be permanently deleted. Servers, agents, and other data will be preserved. After the next scan, only new findings will appear.'
                  : 'You are about to delete all operational data in VulTrack. This action CANNOT be undone.'}
              </p>
            </div>

            <div className="mb-6">
              <label className="block text-sm font-medium text-[#a5d6a7] mb-2">
                Type <code className="bg-red-900/50 text-red-300 px-2 py-1 rounded">{confirmPhrase}</code> to proceed:
              </label>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder={confirmPhrase}
                className="w-full px-4 py-3 bg-[#1a2420] border-2 border-red-600/50 rounded-lg text-[#e8f5e9] placeholder-[#6b7280] focus:outline-none focus:border-red-600 font-mono text-lg"
                autoFocus
              />
            </div>

            {error && (
              <div className="bg-red-900/30 border border-red-600 rounded-lg p-3 mb-4 text-red-300 text-sm">
                {error}
              </div>
            )}

            <div className="flex gap-3">
              <button
                onClick={closeModal}
                className="flex-1 py-3 px-4 bg-[#2d3f36] hover:bg-[#3d4f46] text-[#e8f5e9] rounded-lg font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleReset}
                disabled={resetting || !confirmValid}
                className="flex-1 py-3 px-4 bg-red-600 hover:bg-red-700 disabled:bg-red-900 disabled:opacity-50 text-white rounded-lg font-bold transition-colors flex items-center justify-center gap-2"
              >
                {resetting ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    {isFindingsOnly ? 'Deleting...' : 'Resetting...'}
                  </>
                ) : (
                  <>
                    <Trash2 className="w-5 h-5" />
                    {isFindingsOnly ? 'Delete findings' : 'Delete Permanently'}
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
