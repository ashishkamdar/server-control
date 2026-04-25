"use client";

const PROJECTS = [
  {
    name: "JSG Theater Seating System",
    client: "Jain Social Group, Matunga",
    desc: "Complete theater seating allocation system for 1050+ members. Automated ticket generation, seat assignment with rotation, QR code scanning for event entry, and member management.",
    tech: "Python, Flask, PostgreSQL, QR Integration",
    url: "jsg1.areakpi.in",
    members: "1050+",
  },
  {
    name: "Olistic Studios — Fitness Management",
    client: "Olistic Studios",
    desc: "Fitness studio management software covering member registration, class scheduling, attendance tracking, and business analytics.",
    tech: "Next.js, React, PostgreSQL",
    url: "olistic.areakpi.in",
    members: "Growing",
  },
  {
    name: "Community Member Management",
    client: "Large Kutchi Community Trust",
    desc: "Member CRUD system with insights and analytics for a 5000+ member community organization. Handles member data, reporting, and administrative workflows.",
    tech: "Custom Web Application",
    url: "",
    members: "5000+",
  },
];

const SERVICES = [
  { name: "Member Management Systems", desc: "For communities, clubs, trusts, and organizations" },
  { name: "Booking & Reservation Software", desc: "Halls, sanitariums, sports facilities, appointments" },
  { name: "Event & Ticketing Systems", desc: "Seat allocation, QR scanning, member verification" },
  { name: "Business Management Apps", desc: "CRM, inventory, dashboards, custom workflows" },
  { name: "Fitness & Wellness Software", desc: "Studios, gyms, yoga centers, wellness clinics" },
  { name: "Custom Web Applications", desc: "Tailored solutions for any business need" },
];

export default function PortfolioPage() {
  return (
    <div className="min-h-screen" style={{ background: "var(--background)", color: "var(--foreground)" }}>
      {/* Hero */}
      <div className="mx-auto max-w-4xl px-4 py-12 text-center sm:px-6 sm:py-16">
        <div className="mb-4 inline-flex size-16 items-center justify-center rounded-2xl bg-accent/15 text-2xl font-bold text-accent">AK</div>
        <h1 className="text-4xl font-bold tracking-tight">AREA KPI Technology</h1>
        <p className="mt-3 text-lg text-muted">Custom Software Development</p>
        <p className="mx-auto mt-4 max-w-xl text-sm leading-relaxed text-muted">
          25+ years of software development experience. We build custom management software for organizations, communities, and businesses — member systems, booking platforms, event management, and more.
        </p>
        <div className="mt-6 flex flex-wrap justify-center gap-3">
          <a href="https://wa.me/919819800214?text=Hi%2C%20I%20visited%20your%20portfolio%20and%20need%20custom%20software" target="_blank" rel="noopener"
            className="inline-flex items-center gap-2 rounded-lg bg-[#25D366] px-5 py-3 text-sm font-semibold text-white hover:bg-[#20bd5a]">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="white"><path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347z"/><path d="M12 2C6.477 2 2 6.477 2 12c0 1.89.525 3.66 1.438 5.168L2 22l4.832-1.438A9.955 9.955 0 0012 22c5.523 0 10-4.477 10-10S17.523 2 12 2zm0 18a8 8 0 01-4.243-1.21l-.303-.18-2.866.852.852-2.866-.18-.303A8 8 0 1112 20z"/></svg>
            WhatsApp Us
          </a>
          <a href="tel:+919819800214" className="inline-flex items-center gap-2 rounded-lg border border-border px-5 py-3 text-sm font-semibold hover:bg-surface">
            📞 +91 98198 00214
          </a>
        </div>
      </div>

      {/* Projects */}
      <div className="mx-auto max-w-4xl px-4 pb-12 sm:px-6">
        <h2 className="mb-6 text-center text-2xl font-bold">Our Work</h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {PROJECTS.map((p) => (
            <div key={p.name} className="rounded-xl border border-border bg-surface p-5">
              <h3 className="font-semibold">{p.name}</h3>
              <p className="mt-0.5 text-xs text-accent">{p.client}</p>
              <p className="mt-2 text-sm text-muted">{p.desc}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <span className="rounded-md bg-accent/15 px-2 py-0.5 text-accent">{p.members} users</span>
                <span className="rounded-md bg-surface-hover px-2 py-0.5 text-muted">{p.tech}</span>
              </div>
              {p.url && (
                <a href={`https://${p.url}`} target="_blank" rel="noopener" className="mt-3 block text-xs text-accent hover:underline">{p.url} →</a>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Services */}
      <div className="mx-auto max-w-4xl px-4 pb-12 sm:px-6">
        <h2 className="mb-6 text-center text-2xl font-bold">What We Build</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {SERVICES.map((s) => (
            <div key={s.name} className="rounded-xl border border-border bg-surface p-4">
              <p className="font-medium text-sm">{s.name}</p>
              <p className="mt-1 text-xs text-muted">{s.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* CTA */}
      <div className="mx-auto max-w-4xl px-4 pb-16 text-center sm:px-6">
        <div className="rounded-2xl border border-accent/20 bg-accent/5 p-8">
          <h2 className="text-xl font-bold">Need Custom Software?</h2>
          <p className="mt-2 text-sm text-muted">Tell us what your organization needs. We will build it.</p>
          <a href="https://wa.me/919819800214?text=Hi%2C%20I%20need%20custom%20software%20for%20my%20business" target="_blank" rel="noopener"
            className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-6 py-3 text-sm font-semibold text-white hover:bg-accent-hover">
            Start a Conversation →
          </a>
        </div>
      </div>
    </div>
  );
}
