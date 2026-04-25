import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM proposals ORDER BY created_at DESC");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const p = await req.json();
  const result = await pool.query(
    "INSERT INTO proposals (client_name, project_name, problem, solution, timeline, price, payment_terms, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    [p.client_name, p.project_name, p.problem, p.solution, p.timeline, p.price, p.payment_terms, p.status || "draft"]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const p = await req.json();
  await pool.query(
    "UPDATE proposals SET client_name=$1, project_name=$2, problem=$3, solution=$4, timeline=$5, price=$6, payment_terms=$7, status=$8 WHERE id=$9",
    [p.client_name, p.project_name, p.problem, p.solution, p.timeline, p.price, p.payment_terms, p.status, p.id]
  );
  return Response.json({ ok: true });
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await pool.query("DELETE FROM proposals WHERE id = $1", [id]);
  return Response.json({ ok: true });
}
