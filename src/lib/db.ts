import pg from "pg";
const { Pool } = pg;

const pool = new Pool({
  host: "localhost",
  port: 5432,
  database: "mmam_db",
  user: "mmam_user",
  password: "mmam_secure_2026",
  max: 5,
});

export default pool;
