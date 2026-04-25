import pool from "@/lib/db";

export async function GET() {
  const result = await pool.query("SELECT * FROM weekly_reviews ORDER BY week_start DESC LIMIT 20");
  return Response.json(result.rows);
}

export async function POST(req: Request) {
  const w = await req.json();
  const result = await pool.query(
    `INSERT INTO weekly_reviews (week_start, what_worked, what_didnt, people_contacted, projects_progressed, personality_progress, goals_next_week, mood_rating)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [w.week_start, w.what_worked, w.what_didnt, w.people_contacted, w.projects_progressed, w.personality_progress, w.goals_next_week, w.mood_rating]
  );
  return Response.json(result.rows[0]);
}
