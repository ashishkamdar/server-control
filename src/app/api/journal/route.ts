import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM journal_entries ORDER BY entry_date DESC LIMIT 60");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const j = await req.json();
  const result = await pool.query(
    `INSERT INTO journal_entries (entry_date, mood, energy_level, grooming_done, people_met, practiced, wins, challenges, notes)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [j.entry_date || new Date().toISOString().split("T")[0], j.mood, j.energy_level, j.grooming_done, j.people_met, j.practiced, j.wins, j.challenges, j.notes]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM journal_entries WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
