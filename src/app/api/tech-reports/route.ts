import { NextResponse } from "next/server";
import pool from "@/lib/db";

export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");

    if (id) {
      // Fetch single report with full data
      const result = await pool.query(
        "SELECT id, title, requirements, recommendation, project_plan, whatsapp_summary, created_at FROM tech_reports WHERE id = $1",
        [id]
      );
      if (result.rows.length === 0) return NextResponse.json({ error: "Not found" }, { status: 404 });
      return NextResponse.json(result.rows[0]);
    }

    // List all reports (summary only)
    const result = await pool.query(
      "SELECT id, title, whatsapp_summary, created_at FROM tech_reports ORDER BY created_at DESC"
    );
    return NextResponse.json(result.rows);
  } catch {
    return NextResponse.json({ error: "Failed to fetch reports" }, { status: 500 });
  }
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { title, requirements, recommendation, project_plan, whatsapp_summary } = body;

    const result = await pool.query(
      `INSERT INTO tech_reports (title, requirements, recommendation, project_plan, whatsapp_summary)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, title, created_at`,
      [title, JSON.stringify(requirements), JSON.stringify(recommendation), JSON.stringify(project_plan), whatsapp_summary]
    );

    return NextResponse.json(result.rows[0]);
  } catch {
    return NextResponse.json({ error: "Failed to save report" }, { status: 500 });
  }
}

export async function DELETE(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get("id");
    if (!id) return NextResponse.json({ error: "ID required" }, { status: 400 });

    await pool.query("DELETE FROM tech_reports WHERE id = $1", [id]);
    return NextResponse.json({ success: true });
  } catch {
    return NextResponse.json({ error: "Failed to delete" }, { status: 500 });
  }
}
