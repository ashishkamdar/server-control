import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM follow_ups ORDER BY done ASC, due_date ASC");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const f = await req.json();
  const result = await pool.query(
    "INSERT INTO follow_ups (contact_name, related_project, action, due_date) VALUES ($1,$2,$3,$4) RETURNING *",
    [f.contact_name, f.related_project, f.action, f.due_date]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const f = await req.json();
  await pool.query(
    "UPDATE follow_ups SET done=$1, outcome=$2 WHERE id=$3",
    [f.done, f.outcome || null, f.id]
  );
  return Response.json({ ok: true });
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM follow_ups WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
