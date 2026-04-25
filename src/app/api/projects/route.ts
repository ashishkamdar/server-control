import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query(
    "SELECT * FROM projects ORDER BY created_at DESC"
  );
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const p = await req.json();
  const result = await pool.query(
    `INSERT INTO projects (client_name, community, project_name, description, cost, status, contact_person, contact_role, contact_phone, blocker, next_step, next_date, notes, agreed_amount, received_amount)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
    [p.client_name, p.community, p.project_name, p.description, p.cost, p.status,
     p.contact_person, p.contact_role, p.contact_phone, p.blocker, p.next_step, p.next_date || null, p.notes, p.agreed_amount || 0, p.received_amount || 0]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const p = await req.json();
  const result = await pool.query(
    `UPDATE projects SET client_name=$1, community=$2, project_name=$3, description=$4, cost=$5, status=$6,
     contact_person=$7, contact_role=$8, contact_phone=$9, blocker=$10, next_step=$11, next_date=$12, notes=$13, agreed_amount=$14, received_amount=$15, updated_at=NOW()
     WHERE id=$16 RETURNING *`,
    [p.client_name, p.community, p.project_name, p.description, p.cost, p.status,
     p.contact_person, p.contact_role, p.contact_phone, p.blocker, p.next_step, p.next_date || null, p.notes, p.agreed_amount || 0, p.received_amount || 0, p.id]
  );
  return Response.json(result.rows[0]);
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM projects WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
