import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM revenue_entries ORDER BY entry_date DESC LIMIT 200");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const r = await req.json();
  const result = await pool.query(
    `INSERT INTO revenue_entries (entry_date, type, amount, category, description, project_name)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [r.entry_date || new Date().toISOString().split("T")[0], r.type, r.amount, r.category, r.description, r.project_name]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM revenue_entries WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
