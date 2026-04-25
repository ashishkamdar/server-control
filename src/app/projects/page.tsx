"use client";

import { useEffect, useState } from "react";

export interface FollowUp {
  id: string;
  date: string;
  note: string;
  outcome: string;
}

export interface ChangeRequest {
  id: string;
  date: string;
  request: string;
  status: "pending" | "done" | "rejected";
}

export interface Project {
  id: string;
  clientName: string;
  community: string;
  projectName: string;
  description: string;
  cost: string;
  status: "free" | "quoted" | "in-progress" | "delivered" | "paid" | "blocked";
  contactPerson: string;
  contactRole: string;
  contactPhone: string;
  blocker: string;
  nextStep: string;
  nextDate: string;
  notes: string;
  agreedAmount: number;
  receivedAmount: number;
  followUps: FollowUp[];
  changeRequests: ChangeRequest[];
  createdAt: string;
  updatedAt: string;
}

const STATUS_OPTIONS = [
  { value: "free", label: "Free / Pro Bono", color: "bg-blue-500/15 text-blue-400" },
  { value: "quoted", label: "Quoted", color: "bg-yellow-500/15 text-yellow-400" },
  { value: "in-progress", label: "In Progress", color: "bg-accent/15 text-accent" },
  { value: "delivered", label: "Delivered", color: "bg-emerald-500/15 text-emerald-500" },
  { value: "paid", label: "Paid", color: "bg-emerald-500/15 text-emerald-500" },
  { value: "blocked", label: "Blocked", color: "bg-red-500/15 text-red-400" },
];

const COMMUNITIES = ["Kutchi", "Gujarati", "Marathi", "Punjabi", "Sindhi", "South Indian", "Bengali", "Other"];

const emptyProject: Omit<Project, "id" | "createdAt" | "updatedAt"> = {
  clientName: "",
  community: "Kutchi",
  projectName: "",
  description: "",
  cost: "",
  status: "in-progress",
  contactPerson: "",
  contactRole: "",
  contactPhone: "",
  blocker: "",
  nextStep: "",
  nextDate: "",
  notes: "",
  agreedAmount: 0,
  receivedAmount: 0,
  followUps: [],
  changeRequests: [],
};

export default function ProjectsPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [editing, setEditing] = useState<Project | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [showForm, setShowForm] = useState(false);

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const res = await fetch("/api/projects");
      const data = await res.json();
      // Map DB snake_case to camelCase
      const mapped = data.map((p: Record<string, unknown>) => ({
        id: String(p.id),
        clientName: p.client_name || "",
        community: p.community || "Kutchi",
        projectName: p.project_name || "",
        description: p.description || "",
        cost: p.cost || "",
        status: p.status || "in-progress",
        contactPerson: p.contact_person || "",
        contactRole: p.contact_role || "",
        contactPhone: p.contact_phone || "",
        blocker: p.blocker || "",
        nextStep: p.next_step || "",
        nextDate: p.next_date ? String(p.next_date).split("T")[0] : "",
        notes: p.notes || "",
        agreedAmount: Number(p.agreed_amount) || 0,
        receivedAmount: Number(p.received_amount) || 0,
        followUps: [],
        changeRequests: [],
        createdAt: p.created_at || "",
        updatedAt: p.updated_at || "",
      }));
      setProjects(mapped);
    } catch {
      // Fallback to localStorage if DB unreachable
      const saved = JSON.parse(localStorage.getItem("mmam-projects") || "[]");
      setProjects(saved);
    }
  };

  const save = async (project: Project) => {
    const body = {
      id: isNew ? undefined : project.id,
      client_name: project.clientName,
      community: project.community,
      project_name: project.projectName,
      description: project.description,
      cost: project.cost,
      status: project.status,
      contact_person: project.contactPerson,
      contact_role: project.contactRole,
      contact_phone: project.contactPhone,
      blocker: project.blocker,
      next_step: project.nextStep,
      next_date: project.nextDate || null,
      notes: project.notes,
      agreed_amount: project.agreedAmount || 0,
      received_amount: project.receivedAmount || 0,
    };
    await fetch("/api/projects", {
      method: isNew ? "POST" : "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await fetchProjects();
    setShowForm(false);
    setEditing(null);
    setIsNew(false);
  };

  const deleteProject = async (id: string) => {
    if (!confirm("Delete this project?")) return;
    await fetch("/api/projects", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    await fetchProjects();
  };

  const startNew = () => {
    setEditing({
      ...emptyProject,
      id: Date.now().toString(),
      createdAt: new Date().toISOString().split("T")[0],
      updatedAt: new Date().toISOString().split("T")[0],
    });
    setIsNew(true);
    setShowForm(true);
  };

  const startEdit = (project: Project) => {
    setEditing({ ...project });
    setIsNew(false);
    setShowForm(true);
  };

  const statusInfo = (status: string) => STATUS_OPTIONS.find((s) => s.value === status) || STATUS_OPTIONS[2];

  // Inline quick update — saves one field directly to DB
  const quickUpdate = async (id: string, field: string, value: string) => {
    const project = projects.find((p) => p.id === id);
    if (!project) return;
    const fieldMap: Record<string, string> = {
      status: "status", blocker: "blocker", nextStep: "next_step", nextDate: "next_date", notes: "notes", cost: "cost",
    };
    const body = {
      id,
      client_name: project.clientName,
      community: project.community,
      project_name: project.projectName,
      description: project.description,
      cost: field === "cost" ? value : project.cost,
      status: field === "status" ? value : project.status,
      contact_person: project.contactPerson,
      contact_role: project.contactRole,
      contact_phone: project.contactPhone,
      blocker: field === "blocker" ? value : project.blocker,
      next_step: field === "nextStep" ? value : project.nextStep,
      next_date: field === "nextDate" ? value : project.nextDate || null,
      notes: field === "notes" ? value : project.notes,
      agreed_amount: field === "agreedAmount" ? Number(value) : project.agreedAmount || 0,
      received_amount: field === "receivedAmount" ? Number(value) : project.receivedAmount || 0,
    };
    // Optimistic update
    const updateValue = field === "agreedAmount" || field === "receivedAmount" ? Number(value) : value;
    setProjects(projects.map((p) => p.id === id ? { ...p, [field]: updateValue } : p));
    await fetch("/api/projects", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  };

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Projects</h1>
          <p className="mt-2 text-muted">Track all your projects, clients, costs, and progress.</p>
        </div>
        <button
          onClick={startNew}
          className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
        >
          + Add Project
        </button>
      </div>

      {/* Project Form Modal */}
      {showForm && editing && (
        <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 sm:pt-20">
          <div className="w-full max-w-2xl rounded-2xl border border-border bg-[var(--background)] p-5 shadow-2xl sm:p-6">
            <div className="mb-6 flex items-center justify-between">
              <h2 className="text-xl font-semibold">{isNew ? "New Project" : "Edit Project"}</h2>
              <button
                onClick={() => { setShowForm(false); setEditing(null); }}
                className="rounded-lg p-2 text-muted hover:text-[var(--foreground)]"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-5">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-sm font-medium">Client Name *</label>
                  <input type="text" value={editing.clientName} onChange={(e) => setEditing({ ...editing, clientName: e.target.value })} placeholder="e.g., Sunil Saiya" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium">Community</label>
                  <select value={editing.community} onChange={(e) => setEditing({ ...editing, community: e.target.value })} className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none">
                    {COMMUNITIES.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium">Project Name *</label>
                <input type="text" value={editing.projectName} onChange={(e) => setEditing({ ...editing, projectName: e.target.value })} placeholder="e.g., Fitness Studio Management Software" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium">Description</label>
                <textarea value={editing.description} onChange={(e) => setEditing({ ...editing, description: e.target.value })} rows={2} placeholder="What does this software do?" className="w-full resize-none rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1 block text-sm font-medium">Cost / Price</label>
                  <input type="text" value={editing.cost} onChange={(e) => setEditing({ ...editing, cost: e.target.value })} placeholder="e.g., Rs 2,25,000 or Free" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium">Status</label>
                  <select value={editing.status} onChange={(e) => setEditing({ ...editing, status: e.target.value as Project["status"] })} className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none">
                    {STATUS_OPTIONS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="border-t border-border pt-4">
                <p className="mb-3 text-sm font-medium text-muted">Contact Details</p>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div>
                    <label className="mb-1 block text-xs text-muted">Person</label>
                    <input type="text" value={editing.contactPerson} onChange={(e) => setEditing({ ...editing, contactPerson: e.target.value })} placeholder="Name" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted">Role</label>
                    <input type="text" value={editing.contactRole} onChange={(e) => setEditing({ ...editing, contactRole: e.target.value })} placeholder="e.g., Owner, Trustee" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted">Phone</label>
                    <input type="tel" value={editing.contactPhone} onChange={(e) => setEditing({ ...editing, contactPhone: e.target.value })} placeholder="Phone number" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                  </div>
                </div>
              </div>

              <div className="border-t border-border pt-4">
                <p className="mb-3 text-sm font-medium text-muted">Progress & Blockers</p>
                <div className="space-y-3">
                  <div>
                    <label className="mb-1 block text-xs text-muted">Blocker / Challenge</label>
                    <input type="text" value={editing.blocker} onChange={(e) => setEditing({ ...editing, blocker: e.target.value })} placeholder="What's blocking progress?" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="mb-1 block text-xs text-muted">Next Step</label>
                      <input type="text" value={editing.nextStep} onChange={(e) => setEditing({ ...editing, nextStep: e.target.value })} placeholder="What's the next action?" className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                    </div>
                    <div>
                      <label className="mb-1 block text-xs text-muted">Follow-up Date</label>
                      <input type="date" value={editing.nextDate} onChange={(e) => setEditing({ ...editing, nextDate: e.target.value })} className="w-full rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
                    </div>
                  </div>
                </div>
              </div>

              {/* Follow-ups */}
              {!isNew && (
                <div className="border-t border-border pt-4">
                  <div className="mb-3 flex items-center justify-between">
                    <p className="text-sm font-medium text-muted">Follow-ups</p>
                    <button
                      type="button"
                      onClick={() => {
                        const note = prompt("Follow-up note:");
                        if (!note) return;
                        const outcome = prompt("Outcome (what happened):") || "";
                        setEditing({
                          ...editing,
                          followUps: [...(editing.followUps || []), { id: Date.now().toString(), date: new Date().toISOString().split("T")[0], note, outcome }],
                        });
                      }}
                      className="rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                    >
                      + Add Follow-up
                    </button>
                  </div>
                  {(editing.followUps || []).length > 0 && (
                    <div className="space-y-2">
                      {(editing.followUps || []).map((f) => (
                        <div key={f.id} className="flex items-start justify-between rounded-lg bg-[var(--background)] px-3 py-2 text-xs">
                          <div>
                            <span className="font-mono text-muted">{f.date}</span>
                            <span className="mx-2 text-muted">—</span>
                            <span>{f.note}</span>
                            {f.outcome && <p className="mt-0.5 text-muted">Outcome: {f.outcome}</p>}
                          </div>
                          <button onClick={() => setEditing({ ...editing, followUps: (editing.followUps || []).filter((x) => x.id !== f.id) })} className="ml-2 text-muted hover:text-red-400">×</button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Change Requests */}
              {!isNew && (
                <div className="border-t border-border pt-4">
                  <div className="mb-3 flex items-center justify-between">
                    <p className="text-sm font-medium text-muted">Change Requests</p>
                    <button
                      type="button"
                      onClick={() => {
                        const request = prompt("What did the client request?");
                        if (!request) return;
                        setEditing({
                          ...editing,
                          changeRequests: [...(editing.changeRequests || []), { id: Date.now().toString(), date: new Date().toISOString().split("T")[0], request, status: "pending" }],
                        });
                      }}
                      className="rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                    >
                      + Add Change Request
                    </button>
                  </div>
                  {(editing.changeRequests || []).length > 0 && (
                    <div className="space-y-2">
                      {(editing.changeRequests || []).map((cr) => (
                        <div key={cr.id} className="flex items-start justify-between rounded-lg bg-[var(--background)] px-3 py-2 text-xs">
                          <div className="flex-1">
                            <span className="font-mono text-muted">{cr.date}</span>
                            <span className="mx-2 text-muted">—</span>
                            <span>{cr.request}</span>
                          </div>
                          <div className="ml-2 flex items-center gap-1">
                            <select
                              value={cr.status}
                              onChange={(e) => setEditing({ ...editing, changeRequests: (editing.changeRequests || []).map((x) => x.id === cr.id ? { ...x, status: e.target.value as ChangeRequest["status"] } : x) })}
                              className="rounded border border-border bg-surface px-1.5 py-0.5 text-xs"
                            >
                              <option value="pending">Pending</option>
                              <option value="done">Done</option>
                              <option value="rejected">Rejected</option>
                            </select>
                            <button onClick={() => setEditing({ ...editing, changeRequests: (editing.changeRequests || []).filter((x) => x.id !== cr.id) })} className="text-muted hover:text-red-400">×</button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              <div>
                <label className="mb-1 block text-sm font-medium">Notes</label>
                <textarea value={editing.notes} onChange={(e) => setEditing({ ...editing, notes: e.target.value })} rows={3} placeholder="Any additional notes, history, or strategy..." className="w-full resize-none rounded-lg border border-border bg-surface px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button onClick={() => { setShowForm(false); setEditing(null); }} className="rounded-lg border border-border px-4 py-2.5 text-sm font-medium text-muted hover:text-[var(--foreground)]">
                  Cancel
                </button>
                <button
                  onClick={() => save({ ...editing, updatedAt: new Date().toISOString().split("T")[0] })}
                  disabled={!editing.clientName.trim() || !editing.projectName.trim()}
                  className="rounded-lg bg-accent px-6 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover disabled:opacity-40"
                >
                  {isNew ? "Add Project" : "Save Changes"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Project cards */}
      {projects.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-border py-20 text-center">
          <p className="text-lg font-medium">No projects yet</p>
          <p className="mt-1 text-sm text-muted">Add your first project to start tracking.</p>
          <button onClick={startNew} className="mt-4 rounded-lg bg-accent px-4 py-2 text-sm font-semibold text-white">
            + Add Project
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          {projects.map((p) => {
            const si = statusInfo(p.status);
            return (
              <div key={p.id} className="group rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="mb-1 flex flex-wrap items-center gap-2">
                      <span className="text-lg font-semibold">{p.clientName}</span>
                      <select
                        value={p.status}
                        onChange={(e) => quickUpdate(p.id, "status", e.target.value)}
                        className={`rounded-md border-0 px-2 py-0.5 text-xs font-medium ${si.color} cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent`}
                      >
                        {STATUS_OPTIONS.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                      </select>
                      <span className="rounded-md bg-accent/15 px-2 py-0.5 text-xs font-medium text-accent">{p.community}</span>
                    </div>
                    <p className="text-sm font-medium text-accent">{p.projectName}</p>
                    {p.cost && <p className="mt-0.5 font-mono text-sm font-bold">{p.cost}</p>}
                    {/* Payment Tracker */}
                    {(p.agreedAmount > 0 || p.receivedAmount > 0) && (
                      <div className="mt-2 rounded-lg bg-[var(--background)] p-3">
                        <div className="mb-2 flex items-center justify-between text-xs">
                          <span className="text-muted">Payment Progress</span>
                          <span className="font-mono font-bold">
                            <span className="text-emerald-500">₹{new Intl.NumberFormat("en-IN").format(p.receivedAmount)}</span>
                            <span className="text-muted"> / ₹{new Intl.NumberFormat("en-IN").format(p.agreedAmount)}</span>
                          </span>
                        </div>
                        <div className="h-2.5 rounded-full bg-border">
                          <div
                            className="h-2.5 rounded-full bg-emerald-500 transition-all duration-300"
                            style={{ width: `${p.agreedAmount > 0 ? Math.min((p.receivedAmount / p.agreedAmount) * 100, 100) : 0}%` }}
                          />
                        </div>
                        <div className="mt-2 flex gap-2">
                          <button
                            onClick={() => {
                              const amt = prompt("Log payment received (₹):");
                              if (!amt) return;
                              const newReceived = p.receivedAmount + Number(amt);
                              quickUpdate(p.id, "receivedAmount", String(newReceived));
                            }}
                            className="rounded px-2 py-1 text-xs font-medium text-emerald-500 hover:bg-emerald-500/10"
                          >
                            + Log Payment
                          </button>
                          {p.agreedAmount === 0 && (
                            <button
                              onClick={() => {
                                const amt = prompt("Set agreed amount (₹):");
                                if (!amt) return;
                                quickUpdate(p.id, "agreedAmount", amt);
                              }}
                              className="rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                            >
                              Set Agreed Amount
                            </button>
                          )}
                        </div>
                      </div>
                    )}
                    {p.agreedAmount === 0 && p.receivedAmount === 0 && p.status !== "free" && (
                      <button
                        onClick={() => {
                          const amt = prompt("Set agreed project amount (₹):");
                          if (!amt) return;
                          quickUpdate(p.id, "agreedAmount", amt);
                        }}
                        className="mt-1 rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                      >
                        + Set Project Amount
                      </button>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => startEdit(p)} className="rounded-lg p-2 text-muted opacity-0 transition-all hover:bg-surface-hover hover:text-[var(--foreground)] group-hover:opacity-100">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-4">
                        <path strokeLinecap="round" strokeLinejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10" />
                      </svg>
                    </button>
                    <button onClick={() => deleteProject(p.id)} className="rounded-lg p-2 text-muted opacity-0 transition-all hover:bg-red-500/10 hover:text-red-400 group-hover:opacity-100">
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-4">
                        <path strokeLinecap="round" strokeLinejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
                      </svg>
                    </button>
                  </div>
                </div>

                {p.description && <p className="mt-2 text-sm text-muted">{p.description}</p>}

                {/* Compact summary line: blocker + next step always visible */}
                {(p.blocker || p.nextStep) && (
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
                    {p.blocker && (
                      <span className="text-red-400">
                        <span className="font-medium">Blocker:</span> {p.blocker}
                      </span>
                    )}
                    {p.nextStep && (
                      <span className="text-accent">
                        <span className="font-medium">Next:</span> {p.nextStep}
                        {p.nextDate && <span className="ml-1 font-mono text-accent/60">({p.nextDate})</span>}
                      </span>
                    )}
                  </div>
                )}

                {/* Collapsible details section */}
                <details className="mt-3 rounded-lg border border-border/50">
                  <summary className="cursor-pointer px-4 py-2.5 text-xs font-semibold text-muted hover:text-[var(--foreground)] select-none">
                    Details & Actions
                    {p.notes ? ` \u00B7 ${p.notes.split('\n').filter(l => l.trim()).length} log entries` : ""}
                    {p.followUps?.length ? ` \u00B7 ${p.followUps.length} follow-ups` : ""}
                    {p.changeRequests?.length ? ` \u00B7 ${p.changeRequests.length} CRs` : ""}
                  </summary>
                  <div className="space-y-4 px-4 pb-4 pt-2">

                    {/* Contact + Blocker + Next Step (editable) */}
                    <div className="grid gap-3 text-sm sm:grid-cols-2">
                      {p.contactPerson && (
                        <div className="flex items-start gap-2">
                          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mt-0.5 size-4 shrink-0 text-muted">
                            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
                          </svg>
                          <div>
                            <span className="font-medium">{p.contactPerson}</span>
                            {p.contactRole && <span className="text-muted"> — {p.contactRole}</span>}
                            {p.contactPhone && <p className="font-mono text-xs text-muted">{p.contactPhone}</p>}
                          </div>
                        </div>
                      )}
                      <div className="flex items-start gap-2">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mt-2 size-4 shrink-0 text-red-400">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
                        </svg>
                        <input
                          type="text"
                          value={p.blocker}
                          onChange={(e) => setProjects(projects.map((x) => x.id === p.id ? { ...x, blocker: e.target.value } : x))}
                          onBlur={(e) => quickUpdate(p.id, "blocker", e.target.value)}
                          placeholder="Add blocker..."
                          className="w-full rounded border-0 bg-transparent px-1 py-1 text-sm text-red-400 placeholder:text-red-400/40 focus:bg-surface focus:outline-none focus:ring-1 focus:ring-red-400/30"
                        />
                      </div>
                    </div>

                    {/* Editable Next Step */}
                    <div className="rounded-lg bg-accent/5 p-3">
                      <div className="flex items-start gap-2">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="mt-1.5 size-4 shrink-0 text-accent">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3" />
                        </svg>
                        <div className="flex-1">
                          <input
                            type="text"
                            value={p.nextStep}
                            onChange={(e) => setProjects(projects.map((x) => x.id === p.id ? { ...x, nextStep: e.target.value } : x))}
                            onBlur={(e) => quickUpdate(p.id, "nextStep", e.target.value)}
                            placeholder="What's the next step?"
                            className="w-full rounded border-0 bg-transparent px-1 py-0.5 text-xs text-accent placeholder:text-accent/40 focus:bg-surface focus:outline-none focus:ring-1 focus:ring-accent/30"
                          />
                          <input
                            type="date"
                            value={p.nextDate}
                            onChange={(e) => { setProjects(projects.map((x) => x.id === p.id ? { ...x, nextDate: e.target.value } : x)); quickUpdate(p.id, "nextDate", e.target.value); }}
                            className="mt-1 rounded border-0 bg-transparent px-1 py-0.5 font-mono text-xs text-accent/60 focus:bg-surface focus:outline-none focus:ring-1 focus:ring-accent/30"
                          />
                        </div>
                      </div>
                    </div>

                    {/* Quick Add Update / Conversation Log */}
                    <div className="border-t border-border pt-3">
                      <div className="mb-2 flex items-center justify-between">
                        <p className="text-xs font-medium text-muted">Updates / Conversation Log</p>
                        <button
                          onClick={() => {
                            const update = prompt("What happened? (conversation, decision, update):");
                            if (!update) return;
                            const current = p.notes || "";
                            const timestamp = new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
                            const newNotes = `[${timestamp}] ${update}\n${current}`;
                            quickUpdate(p.id, "notes", newNotes);
                          }}
                          className="rounded px-2 py-1 text-xs font-medium text-accent hover:bg-accent/10"
                        >
                          + Add Update
                        </button>
                      </div>
                      {p.notes && (
                        <div className="max-h-64 overflow-y-auto rounded-lg bg-[var(--background)] px-3 py-3">
                          <div className="divide-y divide-border/40">
                            {p.notes.split('\n').filter(l => l.trim()).map((line, i) => {
                              const isHeader = line.startsWith('===');
                              const isTimestamp = line.startsWith('[');
                              const isDivider = line.startsWith('---');
                              if (isDivider) return <hr key={i} className="border-border" />;
                              if (isHeader) return <p key={i} className="py-2 text-xs font-bold text-accent">{line.replace(/===/g, '').trim()}</p>;
                              if (isTimestamp) return <p key={i} className="py-2.5 text-xs leading-relaxed"><span className="font-mono text-accent">{line.match(/\[.*?\]/)?.[0]}</span> {line.replace(/\[.*?\]\s*/, '')}</p>;
                              return <p key={i} className="py-2.5 text-xs leading-relaxed text-muted">{line}</p>;
                            })}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Follow-ups on card */}
                    {p.followUps && p.followUps.length > 0 && (
                      <div className="border-t border-border pt-3">
                        <p className="mb-1 text-xs font-medium text-muted">Follow-ups ({p.followUps.length})</p>
                        <div className="space-y-1">
                          {p.followUps.slice(0, 3).map((f) => (
                            <div key={f.id} className="text-xs">
                              <span className="font-mono text-muted">{f.date}</span>
                              <span className="mx-1 text-muted">—</span>
                              <span>{f.note}</span>
                              {f.outcome && <span className="text-muted"> → {f.outcome}</span>}
                            </div>
                          ))}
                          {p.followUps.length > 3 && <p className="text-xs text-muted">+{p.followUps.length - 3} more</p>}
                        </div>
                      </div>
                    )}

                    {/* Change Requests on card */}
                    {p.changeRequests && p.changeRequests.length > 0 && (
                      <div className="border-t border-border pt-3">
                        <p className="mb-1 text-xs font-medium text-muted">Change Requests ({p.changeRequests.length})</p>
                        <div className="space-y-1">
                          {p.changeRequests.slice(0, 3).map((cr) => (
                            <div key={cr.id} className="flex items-center gap-2 text-xs">
                              <span className={`size-1.5 rounded-full ${cr.status === "done" ? "bg-emerald-500" : cr.status === "rejected" ? "bg-red-400" : "bg-yellow-400"}`} />
                              <span>{cr.request}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Pricing advice button */}
                    <div className="border-t border-border pt-3">
                      <button
                        onClick={() => {
                          const query = `I need pricing guidance for this project:
- Client: ${p.clientName} (${p.community} community)
- Project: ${p.projectName}
- Description: ${p.description}
- Current price: ${p.cost || "not set"}
- Status: ${p.status}

Tell me:
1. What should I charge for this? Consider Indian market rates, the complexity, and the client's community/wealth level.
2. Should I offer monthly/annual maintenance charges? How much?
3. How many years of free support should I give?
4. What are my costs? (server hosting: shared vs dedicated, domain, SSL, my time)
5. What's the ROI for me? Is this project worth it strategically even if the money is low?
6. How to present the pricing to the client without sounding greedy or undervaluing myself.`;
                          window.open("/chat?q=" + encodeURIComponent(query), "_self");
                        }}
                        className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium text-accent hover:bg-accent/10"
                      >
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="size-3.5">
                          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v12m-3-2.818.879.659c1.171.879 3.07.879 4.242 0 1.172-.879 1.172-2.303 0-3.182C13.536 12.219 12.768 12 12 12c-.725 0-1.45-.22-2.003-.659-1.106-.879-1.106-2.303 0-3.182s2.9-.879 4.006 0l.415.33M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
                        </svg>
                        Get Pricing Advice
                      </button>
                    </div>

                  </div>
                </details>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
