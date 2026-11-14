
import os
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
from psycopg.types.json import Jsonb
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash

from policy import check_access
from scanner import scan_target, scan_website


app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "zero_trust_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
    "port": int(os.getenv("DB_PORT", "5432")),
}


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db_connection():
    if not DB_CONFIG["password"]:
        raise RuntimeError("Set DB_PASSWORD in PowerShell.")
    return psycopg.connect(**DB_CONFIG)


def init_db():
    """Create only the new website scan table."""
    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS website_scans (
                    id BIGSERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    username VARCHAR(100),
                    website TEXT NOT NULL,
                    hostname VARCHAR(253),
                    risk_score INTEGER NOT NULL,
                    decision VARCHAR(20) NOT NULL,
                    reason TEXT,
                    status_code INTEGER,
                    scan_result JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        connection.commit()
    finally:
        connection.close()


def insert_available_row(cursor, table, values):
    """Insert only columns that exist in the selected table."""
    cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
    """, (table,))

    columns = {row[0] for row in cursor.fetchall()}
    chosen = {k: v for k, v in values.items() if k in columns}

    if not chosen:
        return

    names = list(chosen.keys())
    column_sql = ", ".join(f'"{name}"' for name in names)
    placeholders = ", ".join(["%s"] * len(names))

    cursor.execute(
        f'INSERT INTO "{table}" ({column_sql}) VALUES ({placeholders})',
        tuple(chosen[name] for name in names)
    )


# --------------------------------------------------
# AUTHENTICATION
# --------------------------------------------------

def make_token(user):
    now = datetime.now(timezone.utc)

    return jwt.encode(
        {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )


def get_authenticated_user():
    header = request.headers.get("Authorization", "")

    if not header.startswith("Bearer "):
        return None

    token = header.split(" ", 1)[1].strip()

    try:
        return jwt.decode(
            token,
            app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.PyJWTError:
        return None


# --------------------------------------------------
# SAVE IP SCAN RESULTS
# --------------------------------------------------

def save_scan_result(user, target, result, decision):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            open_ports = result.get("open_ports", [])

            cursor.execute("""
                INSERT INTO scans
                    (user_id, target, risk_score, decision,
                     reason, total_open_ports)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                user["user_id"],
                target,
                result["risk_score"],
                decision["decision"],
                decision["reason"],
                len(open_ports),
            ))

            scan_id = cursor.fetchone()[0]

            for item in open_ports:
                insert_available_row(cursor, "vulnerabilities", {
                    "scan_id": scan_id,
                    "port": item.get("port"),
                    "protocol": item.get("protocol"),
                    "service": item.get("service"),
                    "version": item.get("version", "Unknown"),
                    "description": (
                        f"Open port {item.get('port')}: "
                        f"{item.get('service', 'Unknown service')}"
                    ),
                })

            insert_available_row(cursor, "access_logs", {
                "user_id": user["user_id"],
                "username": user.get("username"),
                "action": "NETWORK_SCAN",
                "details": f"Target={target}; risk={result['risk_score']}",
                "target": target,
                "decision": decision["decision"],
                "risk_score": result["risk_score"],
                "ip_address": request.remote_addr,
            })

        connection.commit()
        return scan_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# SAVE WEBSITE SCAN RESULTS
# --------------------------------------------------

def save_website_scan(user, result, decision):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO website_scans
                    (user_id, username, website, hostname,
                     risk_score, decision, reason, status_code,
                     scan_result)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                user["user_id"],
                user.get("username"),
                result.get("website", ""),
                result.get("hostname", ""),
                result["risk_score"],
                decision["decision"],
                decision["reason"],
                result.get("status_code"),
                Jsonb(result),
            ))

            scan_id = cursor.fetchone()[0]

            insert_available_row(cursor, "access_logs", {
                "user_id": user["user_id"],
                "username": user.get("username"),
                "action": "WEBSITE_SCAN",
                "details": (
                    f"Website={result.get('website')}; "
                    f"risk={result['risk_score']}"
                ),
                "target": result.get("website"),
                "decision": decision["decision"],
                "risk_score": result["risk_score"],
                "ip_address": request.remote_addr,
            })

        connection.commit()
        return scan_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# --------------------------------------------------
# HOME AND HEALTH
# --------------------------------------------------

@app.get("/")
def home():
    return jsonify({
        "project": "Zero Trust Identity & Access Management Proxy",
        "status": "Backend is running",
        "message": "Never Trust, Always Verify",
    })


@app.get("/api/health")
def health():
    connection = None

    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        return jsonify({
            "status": "healthy",
            "database": "connected",
        }), 200

    except Exception:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "unhealthy",
            "database": "not connected",
        }), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE username = %s
            """, (username,))

            row = cursor.fetchone()

        if row is None:
            return jsonify({"error": "Invalid username or password"}), 401

        user_id, db_username, password_hash, role, is_active = row

        if not is_active or not check_password_hash(password_hash, password):
            return jsonify({"error": "Invalid username or password"}), 401

        user = {
            "id": user_id,
            "username": db_username,
            "role": role,
        }

        return jsonify({
            "message": "Login successful",
            "token": make_token(user),
            "user": user,
        }), 200

    except Exception:
        app.logger.exception("Login failed")
        return jsonify({"error": "Login failed. Check database connection."}), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# ADMIN
# --------------------------------------------------

@app.get("/api/admin")
def admin():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    if user.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403

    return jsonify({
        "message": "Admin access granted",
        "username": user.get("username"),
        "role": user.get("role"),
    }), 200


# --------------------------------------------------
# ZERO TRUST POLICY CHECK
# --------------------------------------------------

@app.post("/api/policy-check")
def policy_check():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    data = request.get_json(silent=True) or {}
    risk_score = data.get("risk_score")

    if (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, int)
        or not 0 <= risk_score <= 100
    ):
        return jsonify({
            "error": "risk_score must be an integer from 0 to 100"
        }), 400

    decision = check_access(user.get("role"), risk_score)

    return jsonify({
        "username": user.get("username"),
        "role": user.get("role"),
        "risk_score": risk_score,
        "decision": decision["decision"],
        "reason": decision["reason"],
    }), 200


# --------------------------------------------------
# IP / HOSTNAME SCANNER
# --------------------------------------------------

@app.post("/api/scan")
def scan():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    data = request.get_json(silent=True) or {}
    target = data.get("target")

    if not isinstance(target, str) or not target.strip():
        return jsonify({"error": "A scan target is required"}), 400

    target = target.strip()

    if (
        len(target) > 253
        or any(char.isspace() for char in target)
        or any(char in target for char in "/\\@")
        or target.startswith("-")
    ):
        return jsonify({"error": "Enter a valid hostname or IP address"}), 400

    try:
        result = scan_target(target)

        if not result.get("success"):
            return jsonify({
                "error": result.get("message", "Scan failed")
            }), 400

        decision = check_access(user.get("role"), result["risk_score"])

        scan_id = save_scan_result(user, target, result, decision)

        return jsonify({
            "message": "IP scan completed and saved",
            "scan_id": scan_id,
            "target": target,
            "total_open_ports": result.get("total_open_ports", 0),
            "open_ports": result.get("open_ports", []),
            "risk_score": result["risk_score"],
            "decision": decision["decision"],
            "reason": decision["reason"],
        }), 200

    except Exception:
        app.logger.exception("IP scan failed")
        return jsonify({"error": "IP scan or database save failed"}), 500


# --------------------------------------------------
# WEBSITE SECURITY SCANNER
# --------------------------------------------------

@app.post("/api/scan-website")
def website_scan():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    data = request.get_json(silent=True) or {}
    url = data.get("url")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "A website URL is required"}), 400

    url = url.strip()

    if len(url) > 2048:
        return jsonify({"error": "Website URL is too long"}), 400

    try:
        # Only scan websites you own or have permission to assess.
        result = scan_website(url)

        if not result.get("success"):
            return jsonify({
                "error": result.get("message", "Website scan failed")
            }), 400

        decision = check_access(user.get("role"), result["risk_score"])

        scan_id = save_website_scan(user, result, decision)

        return jsonify({
            "message": "Website security scan completed and saved",
            "scan_id": scan_id,
            "website": result.get("website"),
            "hostname": result.get("hostname"),
            "resolved_ips": result.get("resolved_ips", []),
            "status_code": result.get("status_code"),
            "ssl": result.get("ssl"),
            "security_headers": result.get("security_headers", {}),
            "missing_headers": result.get("missing_headers", []),
            "risk_score": result["risk_score"],
            "decision": decision["decision"],
            "reason": decision["reason"],
        }), 200

    except Exception:
        app.logger.exception("Website scan failed")
        return jsonify({"error": "Website scan or database save failed"}), 500


# --------------------------------------------------
# IP SCAN HISTORY
# --------------------------------------------------

@app.get("/api/scans")
def scan_history():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            if user.get("role") == "admin":
                cursor.execute("""
                    SELECT id, user_id, target, risk_score, decision,
                           reason, total_open_ports
                    FROM scans
                    ORDER BY id DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT id, user_id, target, risk_score, decision,
                           reason, total_open_ports
                    FROM scans
                    WHERE user_id = %s
                    ORDER BY id DESC
                    LIMIT 100
                """, (user["user_id"],))

            rows = cursor.fetchall()

        scans = [{
            "id": row[0],
            "user_id": row[1],
            "target": row[2],
            "risk_score": row[3],
            "decision": row[4],
            "reason": row[5],
            "total_open_ports": row[6],
        } for row in rows]

        return jsonify({"scans": scans}), 200

    except Exception:
        app.logger.exception("IP history failed")
        return jsonify({"error": "Could not retrieve scan history"}), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# WEBSITE SCAN HISTORY
# --------------------------------------------------

@app.get("/api/website-scans")
def website_scan_history():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            if user.get("role") == "admin":
                cursor.execute("""
                    SELECT id, username, website, hostname, risk_score,
                           decision, reason, status_code, created_at
                    FROM website_scans
                    ORDER BY id DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT id, username, website, hostname, risk_score,
                           decision, reason, status_code, created_at
                    FROM website_scans
                    WHERE user_id = %s
                    ORDER BY id DESC
                    LIMIT 100
                """, (user["user_id"],))

            rows = cursor.fetchall()

        history = [{
            "id": row[0],
            "username": row[1],
            "website": row[2],
            "hostname": row[3],
            "risk_score": row[4],
            "decision": row[5],
            "reason": row[6],
            "status_code": row[7],
            "created_at": row[8].isoformat() if row[8] else None,
        } for row in rows]

        return jsonify({"website_scans": history}), 200

    except Exception:
        app.logger.exception("Website history failed")
        return jsonify({"error": "Could not retrieve website scan history"}), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# DASHBOARD STATISTICS
# --------------------------------------------------

@app.get("/api/stats")
def stats():
    user = get_authenticated_user()

    if not user:
        return jsonify({"error": "Missing or invalid token"}), 401

    connection = None

    try:
        connection = get_db_connection()

        with connection.cursor() as cursor:
            if user.get("role") == "admin":
                cursor.execute("""
                    SELECT COUNT(*),
                           COUNT(*) FILTER (WHERE decision = 'ALLOW'),
                           COUNT(*) FILTER (WHERE decision = 'DENY'),
                           COUNT(*) FILTER (WHERE decision = 'STEP_UP')
                    FROM scans
                """)
            else:
                cursor.execute("""
                    SELECT COUNT(*),
                           COUNT(*) FILTER (WHERE decision = 'ALLOW'),
                           COUNT(*) FILTER (WHERE decision = 'DENY'),
                           COUNT(*) FILTER (WHERE decision = 'STEP_UP')
                    FROM scans WHERE user_id = %s
                """, (user["user_id"],))

            ip_stats = cursor.fetchone()

            if user.get("role") == "admin":
                cursor.execute("SELECT COUNT(*) FROM website_scans")
            else:
                cursor.execute(
                    "SELECT COUNT(*) FROM website_scans WHERE user_id = %s",
                    (user["user_id"],)
                )

            website_count = cursor.fetchone()[0]

        return jsonify({
            "total_scans": ip_stats[0] + website_count,
            "ip_scans": ip_stats[0],
            "website_scans": website_count,
            "allowed_scans": ip_stats[1],
            "denied_scans": ip_stats[2],
            "step_up_scans": ip_stats[3],
        }), 200

    except Exception:
        app.logger.exception("Statistics failed")
        return jsonify({"error": "Could not retrieve statistics"}), 500

    finally:
        if connection:
            connection.close()


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    if not app.config["JWT_SECRET_KEY"]:
        raise RuntimeError("Set JWT_SECRET_KEY in PowerShell.")

    init_db()

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))

    print("\n" + "=" * 55)
    print(" ZERO TRUST IAM PROXY & WEBSITE SECURITY SCANNER")
    print(" Never Trust, Always Verify")
    print("=" * 55)
    print(f" Backend: http://{host}:{port}")
    print("=" * 55 + "\n")

    app.run(host=host, port=port, debug=False)
