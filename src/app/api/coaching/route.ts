import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query(
    "SELECT * FROM coaching_entries ORDER BY created_at DESC LIMIT 100"
  );
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const { question, answer, category } = await req.json();

  if (!question || !answer) {
    return Response.json({ error: "Question and answer required" }, { status: 400 });
  }

  const result = await pool.query(
    "INSERT INTO coaching_entries (question, answer, category) VALUES ($1, $2, $3) RETURNING *",
    [question, answer, category || "General"]
  );

  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM coaching_entries WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
