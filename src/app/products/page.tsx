"use client";

import { useEffect, useState } from "react";

interface Product {
  id: number;
  name: string;
  tagline: string;
  description: string;
  features: string;
  target_audience: string;
  price_range: string;
  demo_url: string;
  clients_count: number;
}

export default function ProductsPage() {
  const [products, setProducts] = useState<Product[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ name: "", tagline: "", description: "", features: "", target_audience: "", price_range: "", demo_url: "", clients_count: 0 });

  useEffect(() => { fetch("/api/products").then(r => r.json()).then(setProducts).catch(() => {}); }, []);

  const add = async () => {
    if (!form.name) return;
    await fetch("/api/products", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(form) });
    const r = await fetch("/api/products"); setProducts(await r.json());
    setForm({ name: "", tagline: "", description: "", features: "", target_audience: "", price_range: "", demo_url: "", clients_count: 0 });
    setShowAdd(false);
  };

  const totalPotential = products.length * 10; // rough: each product can be sold to ~10 clients

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 sm:py-10">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Products</h1>
          <p className="mt-2 text-muted">Your ready-made solutions. Sell the same software to multiple clients.</p>
        </div>
        <button onClick={() => setShowAdd(true)} className="rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-white hover:bg-accent-hover">+ Add Product</button>
      </div>

      {/* Strategy card */}
      <div className="mb-8 rounded-xl border border-accent/20 bg-accent/5 p-5">
        <p className="text-sm font-semibold text-accent">The Millionaire Math</p>
        <p className="mt-2 text-sm leading-relaxed">
          You have <strong>{products.length} products</strong>. Each can be sold to 10+ similar organizations.
          That&apos;s <strong>{totalPotential}+ potential deals</strong> without building anything new.
          At Rs 1L average per deployment + Rs 5K/month maintenance = <strong>Rs {totalPotential}L+ in project fees + Rs {products.length * 5 * 12}K/year recurring</strong>.
        </p>
      </div>

      {showAdd && (
        <div className="mb-8 rounded-xl border border-border bg-surface p-5">
          <h2 className="mb-4 text-lg font-semibold">New Product</h2>
          <div className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <input type="text" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Product name *" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.tagline} onChange={e => setForm({ ...form, tagline: e.target.value })} placeholder="One-line tagline" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} rows={2} placeholder="What does it do?" className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <textarea value={form.features} onChange={e => setForm({ ...form, features: e.target.value })} rows={2} placeholder="Key features (comma-separated)" className="w-full resize-none rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            <div className="grid gap-3 sm:grid-cols-2">
              <input type="text" value={form.target_audience} onChange={e => setForm({ ...form, target_audience: e.target.value })} placeholder="Target: samajes, gyms, clinics..." className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
              <input type="text" value={form.price_range} onChange={e => setForm({ ...form, price_range: e.target.value })} placeholder="Price range (e.g., Rs 50K-1.5L)" className="rounded-lg border border-border bg-[var(--background)] px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowAdd(false)} className="rounded-lg border border-border px-4 py-2 text-sm text-muted">Cancel</button>
              <button onClick={add} className="rounded-lg bg-accent px-5 py-2 text-sm font-semibold text-white disabled:opacity-40">Add Product</button>
            </div>
          </div>
        </div>
      )}

      {/* Product cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {products.map(p => (
          <div key={p.id} className="rounded-xl border border-border bg-surface p-5 transition-colors hover:border-accent/30">
            <h3 className="text-lg font-bold">{p.name}</h3>
            {p.tagline && <p className="mt-0.5 text-sm text-accent">{p.tagline}</p>}
            {p.description && <p className="mt-2 text-sm text-muted">{p.description}</p>}
            {p.features && (
              <div className="mt-3 flex flex-wrap gap-1">
                {p.features.split(",").map((f, i) => (
                  <span key={i} className="rounded-md bg-surface-hover px-2 py-0.5 text-xs text-muted">{f.trim()}</span>
                ))}
              </div>
            )}
            <div className="mt-4 space-y-2 text-xs">
              {p.target_audience && <p><strong className="text-muted">For:</strong> {p.target_audience}</p>}
              {p.price_range && <p className="font-mono font-bold text-emerald-500">{p.price_range}</p>}
              {p.demo_url && <a href={`https://${p.demo_url}`} target="_blank" rel="noopener" className="block text-accent hover:underline">{p.demo_url} →</a>}
              <p className="text-muted">{p.clients_count} client{p.clients_count !== 1 ? "s" : ""} deployed</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
