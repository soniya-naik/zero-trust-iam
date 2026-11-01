
import os
from datetime import datetime, timedelta, timezone

import jwt
import psycopg
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import check_password_hash

from policy import check_access
from scanner import scan_target


app = Flask(__name__)
CORS(app)

# Set these environment variables in PowerShell before starting the server.
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "")

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "dbname": os.getenv("DB_NAME", "zero_trust_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
    "port": int(os.getenv("DB_PORT", "5432")),
}


def get_db_connection():
    if not DB_CONFIG["password"]:
        raise RuntimeError(
            "Database password is missing. Set DB_PASSWORD in PowerShell."
        )
    return psycopg.connect(**DB_CONFIG)


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


def insert_available_row(cursor, table, values):
    """
    Insert values matching the columns that exist in a table.
    This helps accommodate small differences in table column names.
    """
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (table,),
    )
    columns = {row[0] for row in cursor.fetchall()}

    chosen = {}
    for name, value in values.items():
        if name in columns:
            chosen[name] = value

    if not chosen:
        raise RuntimeError(f"No matching columns found in table: {table}")

    names = list(chosen.keys())
    column_sql = ", ".join('"' + name + '"' for name in names)
    placeholders = ", ".join(["%s"] * len(names))

    cursor.execute(
        f'INSERT INTO "{table}" ({column_sql}) VALUES ({placeholders})',
        tuple(chosen[name] for name in names),
    )


def save_scan_result(user, target, scan_result, decision):
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            risk_score = scan_result["risk_score"]
            open_ports = scan_result.get("open_ports", [])
            reason = decision["reason"]
            decision_name = decision["decision"]

            cursor.execute(
                """
                INSERT INTO scans
                    (user_id, target, risk_score, decision, reason,
                     total_open_ports)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    user["user_id"],
                    target,
                    risk_score,
                    decision_name,
                    reason,
                    len(open_ports),
                ),
            )
            scan_id = cursor.fetchone()[0]

            for item in open_ports:
                insert_available_row(
                    cursor,
                    "vulnerabilities",
                    {
                        "scan_id": scan_id,
                        "port": item.get("port"),
                        "protocol": item.get("protocol"),
                        "service": item.get("service"),
                        "version": item.get("version", "Unknown"),
                        "name": item.get("service", "Unknown service"),
                        "description": (
                            f"Open port {item.get('port')}: "
                            f"{item.get('service', 'Unknown service')}"
                        ),
                    },
                )

            insert_available_row(
                cursor,
                "access_logs",
                {
                    "user_id": user["user_id"],
                    "username": user.get("username"),
                    "action": "NETWORK_SCAN",
                    "details": (
                        f"Target={target}; risk={risk_score}; "
                        f"decision={decision_name}"
                    ),
                    "target": target,
                    "decision": decision_name,
                    "risk_score": risk_score,
                    "ip_address": request.remote_addr,
                },
            )

        connection.commit()
        return scan_id
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


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
    except Exception as error:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "unhealthy",
            "database": "not connected",
            "error": str(error),
        }), 500
    finally:
        if connection is not None:
            connection.close()


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({
            "error": "Username and password are required"
        }), 400

    connection = None
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, password_hash, role, is_active
                FROM users
                WHERE username = %s
                """,
                (username,),
            )
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
        return jsonify({
            "error": "Login failed. Check the database connection and users table."
        }), 500
    finally:
        if connection is not None:
            connection.close()


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

    # Only scan systems you own or have explicit permission to test.
    # This basic validation blocks common URL/path inputs.
    if (
        len(target) > 253
        or any(char.isspace() for char in target)
        or any(char in target for char in "/\\@")
        or target.startswith("-")
    ):
        return jsonify({
            "error": "Enter a valid hostname or IP address"
        }), 400

    try:
        scan_result = scan_target(target)

        if not scan_result.get("success"):
            return jsonify({
                "error": scan_result.get("message", "Scan failed"),
            }), 400

        decision = check_access(
            user.get("role"),
            scan_result["risk_score"],
        )

        scan_id = save_scan_result(
            user,
            target,
            scan_result,
            decision,
        )

        return jsonify({
            "message": "Scan completed and saved",
            "scan_id": scan_id,
            "target": target,
            "total_open_ports": scan_result.get("total_open_ports", 0),
            "open_ports": scan_result.get("open_ports", []),
            "risk_score": scan_result["risk_score"],
            "decision": decision["decision"],
            "reason": decision["reason"],
        }), 200

    except Exception:
        app.logger.exception("Scan request failed")
        return jsonify({
            "error": (
                "The scan or database save failed. "
                "Check the Flask terminal for details."
            )
        }), 500


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
                cursor.execute(
                    """
                    SELECT id, user_id, target, risk_score, decision,
                           reason, total_open_ports
                    FROM scans
                    ORDER BY id DESC
                    LIMIT 100
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT id, user_id, target, risk_score, decision,
                           reason, total_open_ports
                    FROM scans
                    WHERE user_id = %s
                    ORDER BY id DESC
                    LIMIT 100
                    """,
                    (user["user_id"],),
                )

            rows = cursor.fetchall()

        scans = [
            {
                "id": row[0],
                "user_id": row[1],
                "target": row[2],
                "risk_score": row[3],
                "decision": row[4],
                "reason": row[5],
                "total_open_ports": row[6],
            }
            for row in rows
        ]

        return jsonify({"scans": scans}), 200

    except Exception:
        app.logger.exception("Could not retrieve scan history")
        return jsonify({"error": "Could not retrieve scan history"}), 500
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    if not app.config["JWT_SECRET_KEY"]:
        raise RuntimeError(
            "Set JWT_SECRET_KEY in PowerShell before starting the server."
        )

    app.run(host="127.0.0.1", port=5000, debug=False)
