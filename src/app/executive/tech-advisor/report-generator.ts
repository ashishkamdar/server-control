import {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, ImageRun, AlignmentType, WidthType, BorderStyle,
  PageNumber, NumberFormat, HeadingLevel, ShadingType,
} from "docx";
import type { Recommendation } from "./page";
import type { ProjectPlan } from "./project-planner";

interface ReportInput {
  recommendation: Recommendation;
  projectPlan: ProjectPlan;
  requirements: Record<string, unknown>;
  clientName?: string;
  projectName?: string;
}

const ACCENT = "0284C7"; // sky-600
const MUTED = "64748B";
const DARK = "0F172A";

function heading(text: string, level: typeof HeadingLevel.HEADING_1 = HeadingLevel.HEADING_1): Paragraph {
  return new Paragraph({ heading: level, spacing: { before: 400, after: 200 }, children: [new TextRun({ text, bold: true, color: DARK })] });
}

function subheading(text: string): Paragraph {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 300, after: 150 }, children: [new TextRun({ text, bold: true, color: ACCENT })] });
}

function para(text: string, options?: { bold?: boolean; color?: string; size?: number }): Paragraph {
  return new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text, bold: options?.bold, color: options?.color || DARK, size: options?.size || 20 })] });
}

function bullet(text: string, color?: string): Paragraph {
  return new Paragraph({ bullet: { level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text, size: 20, color: color || DARK })] });
}

function spacer(): Paragraph {
  return new Paragraph({ spacing: { after: 200 }, children: [] });
}

function makeTable(headers: string[], rows: string[][]): Table {
  const headerCells = headers.map(h => new TableCell({
    shading: { type: ShadingType.SOLID, color: "FEF3C7" },
    children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, size: 18, color: DARK })] })],
    width: { size: Math.floor(9000 / headers.length), type: WidthType.DXA },
  }));

  const dataRows = rows.map(row => new TableRow({
    children: row.map(cell => new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text: cell, size: 18, color: DARK })] })],
      borders: { bottom: { style: BorderStyle.SINGLE, size: 1, color: "E7E5E4" } },
    })),
  }));

  return new Table({
    width: { size: 9000, type: WidthType.DXA },
    rows: [new TableRow({ children: headerCells }), ...dataRows],
  });
}

export async function generateWordReport(input: ReportInput): Promise<Blob> {
  const { recommendation: rec, projectPlan: plan, clientName, projectName } = input;

  // Load letterhead image
  const letterheadResponse = await fetch("/letterhead.jpg");
  const letterheadBuffer = await letterheadResponse.arrayBuffer();

  const doc = new Document({
    styles: {
      default: {
        document: { run: { font: "Calibri", size: 20, color: DARK } },
        heading1: { run: { font: "Calibri", size: 32, bold: true, color: DARK } },
        heading2: { run: { font: "Calibri", size: 26, bold: true, color: ACCENT } },
      },
    },
    sections: [{
      properties: {
        page: {
          margin: { top: 1800, bottom: 1200, left: 1200, right: 1200 },
          pageNumbers: { start: 1 },
        },
      },
      headers: {
        default: new Header({
          children: [
            new Paragraph({
              children: [
                new ImageRun({
                  data: letterheadBuffer,
                  transformation: { width: 580, height: 80 },
                  type: "jpg",
                }),
              ],
            }),
            new Paragraph({
              border: { bottom: { style: BorderStyle.SINGLE, size: 2, color: ACCENT } },
              spacing: { after: 200 },
              children: [],
            }),
          ],
        }),
      },
      footers: {
        default: new Footer({
          children: [
            new Paragraph({
              border: { top: { style: BorderStyle.SINGLE, size: 1, color: "E7E5E4" } },
              spacing: { before: 100 },
              alignment: AlignmentType.CENTER,
              children: [
                new TextRun({ text: "Page ", size: 16, color: MUTED }),
                new TextRun({ children: [PageNumber.CURRENT], size: 16, color: MUTED }),
                new TextRun({ text: " of ", size: 16, color: MUTED }),
                new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: MUTED }),
              ],
            }),
            new Paragraph({
              alignment: AlignmentType.CENTER,
              children: [new TextRun({ text: "Confidential — Prepared by AREA KPI Technology", size: 14, color: MUTED, italics: true })],
            }),
          ],
        }),
      },
      children: [
        // ── TITLE PAGE ──
        new Paragraph({ spacing: { before: 2000 }, alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "Technology Stack", size: 48, bold: true, color: DARK }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "& Project Recommendation Report", size: 48, bold: true, color: DARK }),
        ]}),
        spacer(),
        ...(clientName ? [new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: `Prepared for: ${clientName}`, size: 28, bold: true, color: ACCENT }),
        ]})] : []),
        ...(projectName ? [new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: projectName, size: 24, color: MUTED }),
        ]})] : []),
        spacer(),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: `Generated: ${new Date().toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" })}`, size: 24, color: MUTED }),
        ]}),
        spacer(), spacer(),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "Prepared by AREA KPI Technology", size: 22, bold: true, color: ACCENT }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "connect@areakpi.com | +91 98198 00214", size: 20, color: MUTED }),
        ]}),

        // ── TABLE OF CONTENTS (manual) ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("Table of Contents"),
        ...[
          "1. Recommended Technology Stack",
          "2. Security Architecture",
          "3. Server Specifications",
          "4. Technology Licensing",
          "5. Development Phases & Timeline",
          "6. Resource Plan (Human + AI)",
          "7. Backup & Disaster Recovery",
          "8. Performance Targets",
          "9. Scalability Roadmap",
          "10. Risk Assessment",
          "11. Compliance Checklist",
          "12. Go-Live Checklist",
          "13. Maintenance Plan",
          "14. 3-Year Cost Projection",
          "15. Training Plan",
          "16. Technology Alternatives",
          "17. Architecture Diagram",
          "18. Environment Strategy",
          "19. Notification Providers",
          "20. Infrastructure Cost Breakdown",
          "21. Scope of Work",
          "22. Communication Plan",
          "23. Testing Strategy & QA Plan",
          "24. Acceptance Criteria",
          "25. Change Request Process",
          "26. Stakeholder RACI Matrix",
        ].map(item => para(item, { color: ACCENT })),

        // ── 1. TECH STACK ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("1. Recommended Technology Stack"),

        subheading("Frontend"),
        para(rec.frontend.tech, { bold: true }),
        para(rec.frontend.why, { color: MUTED }),
        spacer(),

        subheading("Backend / Middleware"),
        para(rec.backend.tech, { bold: true }),
        para(rec.backend.why, { color: MUTED }),
        spacer(),

        subheading("Database"),
        para(`Primary: ${rec.database.primary}`, { bold: true }),
        para(`Cache: ${rec.database.cache}`),
        ...(rec.database.search ? [para(`Search: ${rec.database.search}`)] : []),
        para(rec.database.why, { color: MUTED }),
        spacer(),

        ...(rec.messaging ? [
          subheading("Message Queue"),
          para(rec.messaging.tech, { bold: true }),
          para(rec.messaging.why, { color: MUTED }),
          spacer(),
        ] : []),

        subheading("Load Balancer"),
        para(rec.loadBalancer.tech, { bold: true }),
        para(rec.loadBalancer.why, { color: MUTED }),
        spacer(),

        subheading("Monitoring"),
        para(rec.monitoring.tech, { bold: true }),
        para(rec.monitoring.why, { color: MUTED }),
        spacer(),

        subheading("CI/CD Pipeline"),
        para(rec.cicd.tech, { bold: true }),
        para(rec.cicd.why, { color: MUTED }),

        // ── 2. SECURITY ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("2. Security Architecture"),
        makeTable(
          ["Layer", "Technology"],
          [
            ["Firewall", rec.security.firewall],
            ["WAF", rec.security.waf],
            ["SSL/TLS", rec.security.ssl],
            ["Authentication", rec.security.auth],
          ]
        ),
        spacer(),
        para(rec.security.why, { color: MUTED }),

        // ── 3. SERVER SPECS ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("3. Server Specifications"),
        para(`Hosting: ${rec.hosting.type}`, { bold: true }),
        spacer(),
        makeTable(
          ["Role", "Qty", "CPU", "RAM", "Disk", "Swap", "Network", "Cost/mo"],
          plan.hardware.map(h => [h.role, String(h.count), h.cpu, h.ram, h.disk, h.swap, h.network, h.monthlyCost])
        ),

        // ── 4. LICENSING ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("4. Technology Licensing"),
        makeTable(
          ["Technology", "License", "Cost", "Notes"],
          plan.licenses.map(l => [l.technology, l.license, l.cost, l.notes])
        ),

        // ── 5. PHASES ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("5. Development Phases & Timeline"),
        ...plan.phases.flatMap(phase => [
          subheading(`Phase ${phase.phase}: ${phase.name} (${phase.duration})`),
          para(`Resources: ${phase.resources}`, { bold: true }),
          para(`Testing: ${phase.testingTime}`, { color: MUTED }),
          para("Tasks:", { bold: true }),
          ...phase.tasks.map(t => bullet(t)),
          para("Deliverables:", { bold: true }),
          ...phase.deliverables.map(d => bullet(d, "16A34A")),
          spacer(),
        ]),

        // ── MILESTONES ──
        subheading("Key Milestones"),
        ...plan.milestones.map(m => para(`${m.date} — ${m.milestone}`)),

        // ── 6. RESOURCES ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("6. Resource Plan"),

        subheading("Human Resources"),
        makeTable(
          ["Role", "Count", "Monthly Rate", "Duration", "Total Cost"],
          plan.resources.humans.map(h => [h.role, String(h.count), h.monthlyRate, h.duration, h.totalCost])
        ),
        para(`Total Human Cost: ${plan.resources.totalHumanCost}`, { bold: true, color: ACCENT }),
        spacer(),

        subheading("AI / Claude Code Resources"),
        makeTable(
          ["Task", "Est. Hours", "Cost/Hour", "Total"],
          plan.resources.claudeCode.map(c => [c.task, c.estimatedHours, c.costPerHour, c.totalCost])
        ),
        para(`Total AI Cost: ${plan.resources.totalAICost}`, { bold: true, color: ACCENT }),
        para(`Savings with AI: ${plan.resources.savingsWithAI}`, { color: MUTED }),

        // ── 7. BACKUP & DR ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("7. Backup & Disaster Recovery"),
        makeTable(
          ["Aspect", "Plan"],
          [
            ["Backup Frequency", plan.backupDR.backupFrequency],
            ["Retention", plan.backupDR.backupRetention],
            ["Storage", plan.backupDR.backupStorage],
            ["RTO (Recovery Time)", plan.backupDR.rto],
            ["RPO (Max Data Loss)", plan.backupDR.rpo],
            ["DR Strategy", plan.backupDR.drStrategy],
            ["Monthly Cost", plan.backupDR.backupCost],
          ]
        ),

        // ── 8. PERFORMANCE ──
        heading("8. Performance Targets"),
        makeTable(
          ["Metric", "Target", "How to Achieve"],
          plan.performanceTargets.targets.map(t => [t.metric, t.target, t.how])
        ),

        // ── 9. SCALABILITY ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("9. Scalability Roadmap"),
        ...plan.scalabilityRoadmap.triggers.map((t, i) => para(`${i + 1}. When: ${t.when} → Action: ${t.action} (${t.cost})`)),

        // ── 10. RISKS ──
        heading("10. Risk Assessment"),
        makeTable(
          ["Risk", "Probability", "Impact", "Mitigation"],
          plan.risks.map(r => [r.risk, r.probability, r.impact, r.mitigation])
        ),

        // ── 11. COMPLIANCE ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("11. Compliance Checklist"),
        makeTable(
          ["Requirement", "Status", "Action"],
          plan.complianceChecklist.items.map(c => [c.requirement, c.status, c.action])
        ),

        // ── 12. GO-LIVE ──
        heading("12. Go-Live Checklist"),
        ...plan.goLiveChecklist.items.map(item => bullet(`[${item.category}] ${item.item}`)),

        // ── 13. MAINTENANCE ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("13. Maintenance Plan"),
        para(`Annual maintenance cost: ${plan.maintenance.annualCost}`, { bold: true, color: ACCENT }),
        spacer(),
        subheading("Monthly Tasks"),
        ...plan.maintenance.monthlyTasks.map(t => bullet(t)),
        subheading("Quarterly Tasks"),
        ...plan.maintenance.quarterlyTasks.map(t => bullet(t)),
        subheading("Annual Tasks"),
        ...plan.maintenance.annualTasks.map(t => bullet(t)),

        // ── 14. 3-YEAR PROJECTION ──
        heading("14. Three-Year Cost Projection"),
        makeTable(
          ["Year", "Infrastructure", "Maintenance", "Licensing", "Total"],
          plan.yearProjection.years.map(y => [y.year, y.infrastructure, y.maintenance, y.licensing, y.total])
        ),

        // ── 15. TRAINING ──
        heading("15. Training Plan"),
        makeTable(
          ["Audience", "Topic", "Duration", "Format"],
          plan.trainingPlan.sessions.map(s => [s.audience, s.topic, s.duration, s.format])
        ),

        // ── 16. ALTERNATIVES ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("16. Technology Alternatives"),
        makeTable(
          ["Layer", "Primary", "Alternative A", "Alternative B", "When to Switch"],
          plan.techAlternatives.alternatives.map(a => [a.layer, a.primary, a.alternativeA, a.alternativeB, a.when])
        ),

        // ── 17. ARCHITECTURE DIAGRAM ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("17. Architecture Diagram"),
        para("Recommended system architecture based on your requirements:", { color: MUTED }),
        spacer(),
        new Paragraph({
          spacing: { after: 200 },
          children: [new TextRun({ text: rec.architectureDiagram, font: "Courier New", size: 16, color: DARK })],
        }),

        // ── 18. ENVIRONMENTS ──
        heading("18. Environment Strategy"),
        makeTable(
          ["Environment", "Purpose", "Specs", "Cost"],
          plan.environments.environments.map(e => [e.name, e.purpose, e.specs, e.cost])
        ),

        // ── 19. NOTIFICATIONS ──
        ...(plan.notifications.providers.length > 0 && plan.notifications.providers[0].channel !== "None selected" ? [
          new Paragraph({ pageBreakBefore: true, children: [] }) as Paragraph,
          heading("19. Notification Providers") as Paragraph,
          makeTable(
            ["Channel", "Provider", "Cost", "Notes"],
            plan.notifications.providers.map(p => [p.channel, p.provider, p.cost, p.notes])
          ) as Table,
        ] : []),

        // ── 20. INFRASTRUCTURE COST BREAKDOWN ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("20. Infrastructure Cost Breakdown"),
        para(`Monthly: ${rec.costs.monthly}`, { bold: true, color: ACCENT }),
        para(`Yearly: ${rec.costs.yearly}`, { bold: true, color: ACCENT }),
        spacer(),
        makeTable(
          ["Item", "Cost"],
          rec.costs.breakdown.map(b => [b.item, b.cost])
        ),

        // ── 21. SCOPE OF WORK ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("21. Scope of Work"),
        subheading("In Scope"),
        ...plan.scopeOfWork.inScope.map(s => bullet(s, "16A34A")),
        spacer(),
        subheading("Out of Scope"),
        ...plan.scopeOfWork.outOfScope.map(s => bullet(s, "EF4444")),
        spacer(),
        subheading("Assumptions"),
        ...plan.scopeOfWork.assumptions.map(s => bullet(s)),
        spacer(),
        subheading("Constraints"),
        ...plan.scopeOfWork.constraints.map(s => bullet(s)),

        // ── 22. COMMUNICATION PLAN ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("22. Communication Plan"),
        makeTable(
          ["Meeting", "Frequency", "Attendees", "Purpose"],
          plan.communicationPlan.meetings.map(m => [m.type, m.frequency, m.attendees, m.purpose])
        ),
        spacer(),
        subheading("Escalation Path"),
        ...plan.communicationPlan.escalationPath.map(s => bullet(s)),
        spacer(),
        subheading("Communication Tools"),
        ...plan.communicationPlan.tools.map(s => bullet(s)),

        // ── 23. TESTING STRATEGY ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("23. Testing Strategy & QA Plan"),
        makeTable(
          ["Test Type", "Tool", "Coverage", "When"],
          plan.testingStrategy.types.map(t => [t.type, t.tool, t.coverage, t.when])
        ),
        spacer(),
        subheading("Quality Gates"),
        ...plan.testingStrategy.qualityGates.map(g => bullet(g)),

        // ── 24. ACCEPTANCE CRITERIA ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("24. Acceptance Criteria"),
        makeTable(
          ["Area", "Criterion", "Verified By"],
          plan.acceptanceCriteria.criteria.map(c => [c.area, c.criterion, c.verifiedBy])
        ),
        spacer(),
        subheading("Sign-off Process"),
        para(plan.acceptanceCriteria.signoffProcess, { color: MUTED }),

        // ── 25. CHANGE REQUEST PROCESS ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("25. Change Request Process"),
        ...plan.changeRequestProcess.steps.map((s, i) => para(`${i + 1}. ${s.step} — Owner: ${s.owner} — SLA: ${s.sla}`)),
        spacer(),
        subheading("Pricing for Changes"),
        para(plan.changeRequestProcess.pricingNote, { color: MUTED }),

        // ── 26. RACI MATRIX ──
        heading("26. Stakeholder RACI Matrix"),
        para("R = Responsible (does the work) · A = Accountable (owns the outcome) · C = Consulted · I = Informed", { color: MUTED, size: 18 }),
        spacer(),
        makeTable(
          ["Activity", "Responsible", "Accountable", "Consulted", "Informed"],
          plan.raciMatrix.rows.map(r => [r.activity, r.responsible, r.accountable, r.consulted, r.informed])
        ),

        // ── GRAND TOTAL ──
        new Paragraph({ pageBreakBefore: true, children: [] }),
        heading("Total Project Investment (First 12 Months)"),
        spacer(),
        makeTable(
          ["Category", "Amount"],
          [
            ["Development", plan.totalProjectCost.development],
            ["Infrastructure (12 months)", plan.totalProjectCost.infrastructure12mo],
            ["Licensing (12 months)", plan.totalProjectCost.licensing12mo],
            ["GRAND TOTAL", plan.totalProjectCost.grand12mo],
          ]
        ),
        spacer(), spacer(),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 400 }, children: [
          new TextRun({ text: "— End of Report —", size: 20, color: MUTED, italics: true }),
        ]}),
        spacer(),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "AREA KPI Technology", size: 22, bold: true, color: ACCENT }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "connect@areakpi.com | +91 98198 00214 | areakpi.in", size: 18, color: MUTED }),
        ]}),
      ],
    }],
  });

  return await Packer.toBlob(doc);
}
