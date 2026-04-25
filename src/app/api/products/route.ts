import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM products ORDER BY clients_count DESC, created_at DESC");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const p = await req.json();
  const result = await pool.query(
    "INSERT INTO products (name, tagline, description, features, target_audience, price_range, demo_url, clients_count) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
    [p.name, p.tagline, p.description, p.features, p.target_audience, p.price_range, p.demo_url, p.clients_count || 0]
  );
  return Response.json(result.rows[0]);
}

export async function PUT(req: Request) {
  const p = await req.json();
  await pool.query(
    "UPDATE products SET name=$1, tagline=$2, description=$3, features=$4, target_audience=$5, price_range=$6, demo_url=$7, clients_count=$8 WHERE id=$9",
    [p.name, p.tagline, p.description, p.features, p.target_audience, p.price_range, p.demo_url, p.clients_count, p.id]
  );
  return Response.json({ ok: true });
}
