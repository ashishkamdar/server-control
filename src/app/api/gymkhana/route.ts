import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM gymkhana_contacts ORDER BY created_at DESC");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const c = await req.json();
  const result = await pool.query(
    `INSERT INTO gymkhana_contacts (name, business, department, age, relationship, software_needs, approach_notes, last_interaction, next_move, potential)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
    [c.name, c.business, c.department, c.age, c.relationship, c.software_needs, c.approach_notes, c.last_interaction, c.next_move, c.potential]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const c = await req.json();
  const result = await pool.query(
    `UPDATE gymkhana_contacts SET name=$1, business=$2, department=$3, age=$4, relationship=$5, software_needs=$6, approach_notes=$7, last_interaction=$8, next_move=$9, potential=$10 WHERE id=$11 RETURNING *`,
    [c.name, c.business, c.department, c.age, c.relationship, c.software_needs, c.approach_notes, c.last_interaction, c.next_move, c.potential, c.id]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM gymkhana_contacts WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
