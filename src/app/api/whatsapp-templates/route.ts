import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM whatsapp_templates ORDER BY category, name");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const t = await req.json();
  const result = await pool.query(
    "INSERT INTO whatsapp_templates (name, category, message) VALUES ($1,$2,$3) RETURNING *",
    [t.name, t.category, t.message]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM whatsapp_templates WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
