"use client";

import { useEffect, useState } from "react";
import Link from "next/link";

interface Project {
  client_name: string;
  project_name: string;
  cost: string;
  status: string;
  next_step: string;
  next_date: string;
  id: number;
}

const statusColors: Record<string, string> = {
  free: "bg-blue-500/15 text-blue-400",
  quoted: "bg-yellow-500/15 text-yellow-400",
  "in-progress": "bg-accent/15 text-accent",
  delivered: "bg-emerald-500/15 text-emerald-500",
  paid: "bg-emerald-500/15 text-emerald-500",
  blocked: "bg-red-500/15 text-red-400",
};

export function ProjectsSummary() {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    fetch("/api/projects")
      .then((res) => res.json())
      .then(setProjects)
      .catch(() => {});
  }, []);

  if (projects.length === 0) {
    return (
      <Link href="/projects" className="flex items-center justify-center rounded-xl border border-dashed border-border p-8 text-sm text-muted hover:border-accent/30">
        Add your first project →
      </Link>
    );
  }

  return (
    <div className="space-y-3">
      {projects.slice(0, 5).map((p) => (
        <Link
          key={p.id}
          href="/projects"
          className="block rounded-xl border border-border bg-surface p-4 transition-colors hover:border-accent/30"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold">{p.client_name}</span>
            <span className={`rounded-md px-2 py-0.5 text-xs font-medium ${statusColors[p.status] || "bg-accent/15 text-accent"}`}>
              {p.status}
            </span>
            {p.cost && <span className="font-mono text-xs font-bold">{p.cost}</span>}
          </div>
          <p className="mt-1 text-sm text-accent">{p.project_name}</p>
          {p.next_step && (
            <p className="mt-2 text-xs text-muted">
              <strong className="text-accent">Next:</strong> {p.next_step}
              {p.next_date && <span className="ml-1 font-mono">({String(p.next_date).split("T")[0]})</span>}
            </p>
          )}
        </Link>
      ))}
    </div>
  );
}
