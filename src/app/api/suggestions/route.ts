import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM suggestions ORDER BY created_at DESC LIMIT 200");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const s = await req.json();
  const result = await pool.query(
    "INSERT INTO suggestions (content, category, source) VALUES ($1,$2,$3) RETURNING *",
    [s.content, s.category || "Strategy", s.source || "Manual"]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM suggestions WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
