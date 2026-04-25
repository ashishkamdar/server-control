import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM chat_sessions ORDER BY updated_at DESC LIMIT 50");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const s = await req.json();
  const result = await pool.query(
    "INSERT INTO chat_sessions (title, messages) VALUES ($1,$2) RETURNING *",
    [s.title, JSON.stringify(s.messages)]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const s = await req.json();
  await pool.query(
    "UPDATE chat_sessions SET title=$1, messages=$2, updated_at=NOW() WHERE id=$3",
    [s.title, JSON.stringify(s.messages), s.id]
  );
  return Response.json({ ok: true });
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM chat_sessions WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
