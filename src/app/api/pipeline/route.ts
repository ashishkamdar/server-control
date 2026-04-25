import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM pipeline ORDER BY CASE stage WHEN 'proposal' THEN 1 WHEN 'negotiating' THEN 2 WHEN 'meeting' THEN 3 WHEN 'interested' THEN 4 WHEN 'aware' THEN 5 WHEN 'won' THEN 6 WHEN 'lost' THEN 7 END, created_at DESC");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const p = await req.json();
  const result = await pool.query(
    "INSERT INTO pipeline (name, company, community, stage, source, estimated_value, next_action, next_date, notes) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *",
    [p.name, p.company, p.community, p.stage || "aware", p.source, p.estimated_value, p.next_action, p.next_date || null, p.notes]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const p = await req.json();

  // Partial update: toggle a strategy checklist item
  if (p.action === "toggle_checklist_item") {
    await pool.query(
      `UPDATE pipeline SET strategy_checklist = jsonb_set(
        strategy_checklist,
        ARRAY['items', $2::text, 'done'],
        $3::jsonb
      ), updated_at=NOW() WHERE id = $1`,
      [p.id, String(p.index), JSON.stringify(p.done)]
    );
    return Response.json({ ok: true });
  }

  // Partial update: add a strategy checklist item
  if (p.action === "add_checklist_item") {
    await pool.query(
      `UPDATE pipeline SET strategy_checklist = jsonb_set(
        strategy_checklist,
        '{items}',
        COALESCE(strategy_checklist->'items', '[]'::jsonb) || $2::jsonb
      ), updated_at=NOW() WHERE id = $1`,
      [p.id, JSON.stringify([{ text: p.text, done: false }])]
    );
    return Response.json({ ok: true });
  }

  // Partial update: add a strategy log entry
  if (p.action === "add_strategy_log") {
    await pool.query(
      `UPDATE pipeline SET strategy_checklist = jsonb_set(
        strategy_checklist,
        '{log}',
        $2::jsonb || COALESCE(strategy_checklist->'log', '[]'::jsonb)
      ), updated_at=NOW() WHERE id = $1`,
      [p.id, JSON.stringify([{ text: p.text, date: new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) }])]
    );
    return Response.json({ ok: true });
  }

  // Full lead update
  await pool.query(
    "UPDATE pipeline SET name=$1, company=$2, community=$3, stage=$4, source=$5, estimated_value=$6, next_action=$7, next_date=$8, notes=$9, updated_at=NOW() WHERE id=$10",
    [p.name, p.company, p.community, p.stage, p.source, p.estimated_value, p.next_action, p.next_date || null, p.notes, p.id]
  );

  // Auto-create project when stage changes to "won"
  if (p.stage === "won") {
    const existing = await pool.query("SELECT id FROM projects WHERE pipeline_id = $1", [p.id]);
    if (existing.rows.length === 0) {
      const amount = parseInt((p.estimated_value || "0").replace(/[^\d]/g, "")) || 0;
      await pool.query(
        `INSERT INTO projects (client_name, community, project_name, description, cost, status, contact_person, notes, agreed_amount, pipeline_id)
         VALUES ($1, $2, $3, $4, $5, 'in-progress', $6, $7, $8, $9)`,
        [
          p.name,
          p.community || "Kutchi",
          p.company || "New Project",
          `Auto-created from pipeline when deal was won.`,
          p.estimated_value || "",
          p.name,
          `[${new Date().toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" })}] Deal won — project auto-created from pipeline.`,
          amount,
          p.id,
        ]
      );
    }
  }

  return Response.json({ ok: true });
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM pipeline WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
