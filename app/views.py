import calendar
import csv
import io
import json
import secrets
import sqlite3
from datetime import date, datetime, timedelta
from functools import wraps

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

bp = Blueprint("main", __name__)


def paginate(items, page, per_page):
    total = len(items)
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    end = start + per_page
    return items[start:end], {"page": page, "per_page": per_page, "total": total, "pages": pages}


def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_symbol = any(not ch.isalnum() for ch in password)
    return has_upper and has_lower and has_digit and has_symbol


def verify_csrf() -> bool:
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if request.endpoint == "main.health":
        return True
    token_session = session.get("csrf_token")
    token_form = request.form.get("csrf_token")
    token_header = request.headers.get("X-CSRF-Token")
    return token_session and (token_form == token_session or token_header == token_session)


def record_login_attempt(email: str, success: bool) -> None:
    db = get_db()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    db.execute(
        "INSERT INTO login_attempts (email, ip_origem, sucesso) VALUES (?, ?, ?)",
        (email, ip, 1 if success else 0),
    )
    db.commit()


def is_rate_limited(email: str) -> bool:
    db = get_db()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    window_minutes = int(current_app.config.get("SECURITY_LOGIN_WINDOW_MINUTES", 15))
    max_attempts = int(current_app.config.get("SECURITY_MAX_LOGIN_ATTEMPTS", 5))
    window_start = (datetime.utcnow() - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    row = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM login_attempts
        WHERE email = ?
          AND ip_origem = ?
          AND sucesso = 0
          AND created_at >= ?
        """,
        (email, ip, window_start),
    ).fetchone()
    return row["total"] >= max_attempts


@bp.before_app_request
def load_logged_in_user():
    if not verify_csrf():
        return Response("CSRF token inválido.", status=400, mimetype="text/plain")

    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
    else:
        last_seen = session.get("last_seen")
        timeout_seconds = int(current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds())
        now = int(datetime.utcnow().timestamp())
        if last_seen and now - int(last_seen) > timeout_seconds:
            session.clear()
            g.user = None
            return redirect(url_for("main.login"))

        g.user = get_db().execute("SELECT * FROM users WHERE id = ? AND deleted_at IS NULL", (user_id,)).fetchone()
        if g.user is None:
            session.clear()
            return redirect(url_for("main.login"))
        session["last_seen"] = now
        session.permanent = True
        if g.user["must_change_password"] and request.endpoint not in {"main.change_password", "main.logout"}:
            if request.endpoint and not request.endpoint.startswith("static"):
                flash("Você precisa trocar a senha antes de continuar.", "error")
                return redirect(url_for("main.change_password"))


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("main.login"))
        return view(**kwargs)

    return wrapped_view


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if g.user is None:
                return redirect(url_for("main.login"))
            if g.user["tipo"] not in allowed_roles:
                flash("Você não tem permissão para acessar esta área.", "error")
                return redirect(url_for("main.dashboard"))
            return view(**kwargs)

        return wrapped_view

    return decorator


@bp.after_app_request
def apply_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com;"
    )
    return response


def log_action(action: str, details: str, before=None, after=None) -> None:
    db = get_db()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    user_agent = request.headers.get("User-Agent", "")
    before_json = json.dumps(before, ensure_ascii=False) if before is not None else ""
    after_json = json.dumps(after, ensure_ascii=False) if after is not None else ""
    db.execute(
        """
        INSERT INTO activity_logs (user_id, acao, detalhes, ip_origem, user_agent, payload_before, payload_after)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (g.user["id"] if g.user else None, action, details, ip, user_agent[:255], before_json, after_json),
    )
    db.commit()


def parse_time(value: str) -> bool:
    try:
        datetime.strptime(value, "%H:%M")
        return True
    except ValueError:
        return False


def validate_reservation_input(form):
    resource_type = form.get("resource_type", "")
    resource_id = form.get("resource_id", "")
    reservation_date = form.get("date", "")
    start_time = form.get("start_time", "")
    end_time = form.get("end_time", "")

    error = None

    if resource_type not in {"sala", "equipamento"}:
        error = "Selecione um tipo de recurso válido."
    elif not resource_id.isdigit():
        error = "Selecione um recurso válido."
    else:
        try:
            datetime.strptime(reservation_date, "%Y-%m-%d")
        except ValueError:
            error = "Data inválida. Use o formato correto."

    if error is None and (not parse_time(start_time) or not parse_time(end_time)):
        error = "Horários inválidos. Use o formato HH:MM."

    if error is None and start_time >= end_time:
        error = "O horário inicial deve ser menor que o horário final."

    if error is None:
        reservation_dt = datetime.strptime(reservation_date, "%Y-%m-%d").date()
        if reservation_dt < date.today():
            error = "Não é permitido criar reserva em data passada."

    if error is None:
        start = datetime.strptime(start_time, "%H:%M")
        end = datetime.strptime(end_time, "%H:%M")
        duration_minutes = int((end - start).total_seconds() // 60)
        max_minutes = int(current_app.config.get("RESERVATION_MAX_MINUTES", 240))
        if duration_minutes > max_minutes:
            error = f"A reserva não pode passar de {max_minutes} minutos."

        start_hour = int(current_app.config.get("RESERVATION_START_HOUR", 7))
        end_hour = int(current_app.config.get("RESERVATION_END_HOUR", 22))
        if start.hour < start_hour or end.hour > end_hour or (end.hour == end_hour and end.minute > 0):
            error = f"Horário fora da janela permitida ({start_hour:02d}:00 às {end_hour:02d}:00)."

    return error, resource_type, int(resource_id) if resource_id.isdigit() else None, reservation_date, start_time, end_time


def has_conflict(resource_type, resource_id, reservation_date, start_time, end_time, reservation_id=None):
    db = get_db()
    query = """
        SELECT id FROM reservations
        WHERE recurso_tipo = ?
          AND recurso_id = ?
          AND data = ?
          AND NOT (horario_fim <= ? OR horario_inicio >= ?)
    """
    params = [resource_type, resource_id, reservation_date, start_time, end_time]

    if reservation_id is not None:
        query += " AND id != ?"
        params.append(reservation_id)

    conflict = db.execute(query, params).fetchone()
    return conflict is not None


def get_resource_name(resource_type, resource_id):
    db = get_db()
    table = "rooms" if resource_type == "sala" else "equipments"
    row = db.execute(f"SELECT nome FROM {table} WHERE id = ? AND deleted_at IS NULL", (resource_id,)).fetchone()
    return row["nome"] if row else "(recurso removido)"


def get_reservations(filters=None):
    db = get_db()
    filters = filters or {}

    where_clauses = []
    params = []

    if filters.get("date"):
        where_clauses.append("r.data = ?")
        params.append(filters["date"])

    if filters.get("room_id"):
        where_clauses.append("(r.recurso_tipo = 'sala' AND r.recurso_id = ?)")
        params.append(filters["room_id"])

    if filters.get("teacher_id"):
        where_clauses.append("r.usuario_id = ?")
        params.append(filters["teacher_id"])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    query = f"""
        SELECT
            r.*,
            COALESCE(u.nome, 'Usuário removido') AS professor_nome,
            CASE
                WHEN r.recurso_tipo = 'sala' THEN rooms.nome
                ELSE equipments.nome
            END AS recurso_nome
        FROM reservations r
        LEFT JOIN users u ON u.id = r.usuario_id
        LEFT JOIN rooms ON r.recurso_tipo = 'sala' AND rooms.id = r.recurso_id AND rooms.deleted_at IS NULL
        LEFT JOIN equipments ON r.recurso_tipo = 'equipamento' AND equipments.id = r.recurso_id AND equipments.deleted_at IS NULL
        {where_sql}
        ORDER BY r.data, r.horario_inicio
    """
    return db.execute(query, params).fetchall()


def reservations_to_dicts(rows):
    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "data": row["data"],
                "horario_inicio": row["horario_inicio"],
                "horario_fim": row["horario_fim"],
                "recurso_tipo": row["recurso_tipo"],
                "recurso_id": row["recurso_id"],
                "recurso_nome": row["recurso_nome"],
                "professor_id": row["usuario_id"],
                "professor_nome": row["professor_nome"],
                "observacao": row["observacao"] or "",
                "data_criacao": row["data_criacao"],
                "data_atualizacao": row["data_atualizacao"],
            }
        )
    return items


def build_csv_response(filename, headers, rows):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(row)

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


def build_month_calendar(year, month):
    db = get_db()
    first_day = f"{year:04d}-{month:02d}-01"
    if month == 12:
        next_month = f"{year + 1:04d}-01-01"
    else:
        next_month = f"{year:04d}-{month + 1:02d}-01"

    counts = db.execute(
        """
        SELECT data, COUNT(*) AS total
        FROM reservations
        WHERE data >= ? AND data < ?
        GROUP BY data
        """,
        (first_day, next_month),
    ).fetchall()

    count_map = {row["data"]: row["total"] for row in counts}
    month_days = calendar.Calendar(firstweekday=0).monthdatescalendar(year, month)

    structured = []
    for week in month_days:
        row = []
        for d in week:
            iso = d.isoformat()
            row.append(
                {
                    "date": iso,
                    "day": d.day,
                    "in_month": d.month == month,
                    "count": count_map.get(iso, 0),
                }
            )
        structured.append(row)

    return structured


@bp.route("/")
def home():
    if g.user:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("main.login"))


@bp.route("/health")
def health():
    return jsonify({"status": "ok", "service": "agenda-escolar"})


@bp.route("/login", methods=("GET", "POST"))
def login():
    if g.user:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if is_rate_limited(email):
            flash("Muitas tentativas de login. Aguarde alguns minutos e tente novamente.", "error")
            return render_template("auth/login.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ? AND deleted_at IS NULL", (email,)).fetchone()

        if user is None or not check_password_hash(user["senha_hash"], password):
            record_login_attempt(email, False)
            flash("Email ou senha inválidos.", "error")
        else:
            record_login_attempt(email, True)
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(24)
            session["user_id"] = user["id"]
            session["last_seen"] = int(datetime.utcnow().timestamp())
            g.user = user
            log_action("login", f"Usuário {user['email']} entrou no sistema")
            return redirect(url_for("main.dashboard"))

    return render_template("auth/login.html")


@bp.route("/logout", methods=("POST",))
@login_required
def logout():
    log_action("logout", f"Usuário {g.user['email']} saiu do sistema")
    session.clear()
    return redirect(url_for("main.login"))


@bp.route("/conta/senha", methods=("GET", "POST"))
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("senha_atual", "")
        new_password = request.form.get("nova_senha", "")
        confirm_password = request.form.get("confirmar_senha", "")

        error = None
        if not check_password_hash(g.user["senha_hash"], current_password):
            error = "Senha atual inválida."
        elif new_password != confirm_password:
            error = "A confirmação da nova senha não confere."
        elif not is_strong_password(new_password):
            error = "A nova senha deve ter 8+ caracteres com maiúscula, minúscula, número e símbolo."

        if error is None:
            db = get_db()
            db.execute(
                """
                UPDATE users
                SET senha_hash = ?, must_change_password = 0, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (generate_password_hash(new_password), g.user["id"]),
            )
            db.commit()
            log_action("senha_alterada", f"Usuário {g.user['email']} alterou a senha")
            flash("Senha alterada com sucesso.", "success")
            return redirect(url_for("main.dashboard"))

        flash(error, "error")

    return render_template("auth/change_password.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    db = get_db()

    totals = {
        "users": db.execute("SELECT COUNT(*) AS c FROM users WHERE deleted_at IS NULL").fetchone()["c"],
        "rooms": db.execute("SELECT COUNT(*) AS c FROM rooms WHERE deleted_at IS NULL").fetchone()["c"],
        "equipments": db.execute("SELECT COUNT(*) AS c FROM equipments WHERE deleted_at IS NULL").fetchone()["c"],
        "reservations": db.execute("SELECT COUNT(*) AS c FROM reservations").fetchone()["c"],
    }

    next_reservations = db.execute(
        """
        SELECT
            r.*,
            u.nome AS professor_nome,
            CASE
                WHEN r.recurso_tipo = 'sala' THEN rooms.nome
                ELSE equipments.nome
            END AS recurso_nome
        FROM reservations r
        JOIN users u ON u.id = r.usuario_id
        LEFT JOIN rooms ON r.recurso_tipo = 'sala' AND rooms.id = r.recurso_id AND rooms.deleted_at IS NULL
        LEFT JOIN equipments ON r.recurso_tipo = 'equipamento' AND equipments.id = r.recurso_id AND equipments.deleted_at IS NULL
        WHERE r.data >= ?
        ORDER BY r.data, r.horario_inicio
        LIMIT 8
        """,
        (date.today().isoformat(),),
    ).fetchall()

    return render_template("dashboard.html", totals=totals, next_reservations=next_reservations)


@bp.route("/agenda")
@login_required
def agenda():
    today = date.today()
    year = request.args.get("year", type=int, default=today.year)
    month = request.args.get("month", type=int, default=today.month)

    filter_date = request.args.get("date", "")
    filter_room = request.args.get("room", "")
    filter_teacher = request.args.get("teacher", "")

    filters = {
        "date": filter_date,
        "room_id": int(filter_room) if filter_room.isdigit() else None,
        "teacher_id": int(filter_teacher) if filter_teacher.isdigit() else None,
    }

    db = get_db()
    rooms = db.execute("SELECT * FROM rooms WHERE deleted_at IS NULL ORDER BY nome").fetchall()
    teachers = db.execute(
        "SELECT id, nome FROM users WHERE tipo = 'professor' AND deleted_at IS NULL ORDER BY nome"
    ).fetchall()

    reservations = get_reservations(filters)
    month_calendar = build_month_calendar(year, month)

    prev_year, prev_month = (year - 1, 12) if month == 1 else (year, month - 1)
    next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)

    return render_template(
        "reservations/agenda.html",
        reservations=reservations,
        rooms=rooms,
        teachers=teachers,
        month_calendar=month_calendar,
        year=year,
        month=month,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        filter_date=filter_date,
        filter_room=filter_room,
        filter_teacher=filter_teacher,
    )


@bp.route("/api/reservas")
@login_required
def reservations_api():
    filter_date = request.args.get("date", "")
    filter_room = request.args.get("room", "")
    filter_teacher = request.args.get("teacher", "")

    filters = {
        "date": filter_date,
        "room_id": int(filter_room) if filter_room.isdigit() else None,
        "teacher_id": int(filter_teacher) if filter_teacher.isdigit() else None,
    }

    rows = get_reservations(filters)
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total": len(rows),
        "items": reservations_to_dicts(rows),
    }
    return jsonify(payload)


@bp.route("/api/docs")
@login_required
def api_docs():
    return jsonify(
        {
            "openapi": "3.0.0",
            "info": {"title": "Agenda Escolar API", "version": "1.0.0"},
            "paths": {
                "/api/reservas": {
                    "get": {
                        "summary": "Lista reservas",
                        "parameters": [
                            {"name": "date", "in": "query", "schema": {"type": "string", "format": "date"}},
                            {"name": "room", "in": "query", "schema": {"type": "integer"}},
                            {"name": "teacher", "in": "query", "schema": {"type": "integer"}},
                        ],
                    }
                },
                "/health": {"get": {"summary": "Healthcheck da aplicação"}},
            },
        }
    )


@bp.route("/reservas/nova", methods=("GET", "POST"))
@roles_required("professor")
def create_reservation():
    db = get_db()
    rooms = db.execute("SELECT * FROM rooms WHERE deleted_at IS NULL ORDER BY nome").fetchall()
    equipments = db.execute("SELECT * FROM equipments WHERE disponivel = 1 AND deleted_at IS NULL ORDER BY nome").fetchall()

    if request.method == "POST":
        error, resource_type, resource_id, reservation_date, start_time, end_time = validate_reservation_input(request.form)
        observacao = request.form.get("observacao", "").strip()

        if error is None:
            table = "rooms" if resource_type == "sala" else "equipments"
            exists = db.execute(f"SELECT id FROM {table} WHERE id = ? AND deleted_at IS NULL", (resource_id,)).fetchone()
            if exists is None:
                error = "Recurso selecionado não existe."

        if error is None and has_conflict(resource_type, resource_id, reservation_date, start_time, end_time):
            error = "Conflito de horário: este recurso já está reservado nesse período."

        if error is None:
            db.execute(
                """
                INSERT INTO reservations
                    (usuario_id, recurso_tipo, recurso_id, data, horario_inicio, horario_fim, observacao)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    g.user["id"],
                    resource_type,
                    resource_id,
                    reservation_date,
                    start_time,
                    end_time,
                    observacao,
                ),
            )
            db.commit()
            resource_name = get_resource_name(resource_type, resource_id)
            log_action("reserva_criada", f"{g.user['nome']} reservou {resource_type} {resource_name} em {reservation_date}")
            flash("Reserva criada com sucesso.", "success")
            return redirect(url_for("main.agenda"))

        flash(error, "error")

    return render_template("reservations/form.html", rooms=rooms, equipments=equipments, reservation=None)


@bp.route("/reservas/<int:reservation_id>/editar", methods=("GET", "POST"))
@login_required
def edit_reservation(reservation_id):
    db = get_db()
    reservation = db.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()

    if reservation is None:
        flash("Reserva não encontrada.", "error")
        return redirect(url_for("main.agenda"))

    is_owner = reservation["usuario_id"] == g.user["id"]
    is_admin = g.user["tipo"] == "admin"

    if not (is_owner or is_admin):
        flash("Apenas o criador ou um administrador pode editar esta reserva.", "error")
        return redirect(url_for("main.agenda"))

    rooms = db.execute("SELECT * FROM rooms WHERE deleted_at IS NULL ORDER BY nome").fetchall()
    equipments = db.execute("SELECT * FROM equipments WHERE disponivel = 1 AND deleted_at IS NULL ORDER BY nome").fetchall()

    if request.method == "POST":
        error, resource_type, resource_id, reservation_date, start_time, end_time = validate_reservation_input(request.form)
        observacao = request.form.get("observacao", "").strip()

        if error is None:
            table = "rooms" if resource_type == "sala" else "equipments"
            exists = db.execute(f"SELECT id FROM {table} WHERE id = ? AND deleted_at IS NULL", (resource_id,)).fetchone()
            if exists is None:
                error = "Recurso selecionado não existe."

        if error is None and has_conflict(
            resource_type, resource_id, reservation_date, start_time, end_time, reservation_id=reservation_id
        ):
            error = "Conflito de horário: este recurso já está reservado nesse período."

        if error is None:
            db.execute(
                """
                UPDATE reservations
                SET recurso_tipo = ?, recurso_id = ?, data = ?, horario_inicio = ?, horario_fim = ?,
                    observacao = ?, data_atualizacao = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    resource_type,
                    resource_id,
                    reservation_date,
                    start_time,
                    end_time,
                    observacao,
                    reservation_id,
                ),
            )
            db.commit()
            log_action("reserva_editada", f"Reserva #{reservation_id} foi editada por {g.user['email']}")
            flash("Reserva atualizada com sucesso.", "success")
            return redirect(url_for("main.agenda"))

        flash(error, "error")

    return render_template("reservations/form.html", rooms=rooms, equipments=equipments, reservation=reservation)


@bp.route("/reservas/<int:reservation_id>/cancelar", methods=("POST",))
@login_required
def cancel_reservation(reservation_id):
    db = get_db()
    reservation = db.execute("SELECT * FROM reservations WHERE id = ?", (reservation_id,)).fetchone()

    if reservation is None:
        flash("Reserva não encontrada.", "error")
        return redirect(url_for("main.agenda"))

    is_owner = reservation["usuario_id"] == g.user["id"]
    is_admin = g.user["tipo"] == "admin"

    if not (is_owner or is_admin):
        flash("Apenas o criador ou um administrador pode cancelar.", "error")
        return redirect(url_for("main.agenda"))

    db.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))
    db.commit()
    log_action("reserva_cancelada", f"Reserva #{reservation_id} cancelada por {g.user['email']}")
    flash("Reserva cancelada com sucesso.", "success")
    return redirect(url_for("main.agenda"))


@bp.route("/historico")
@roles_required("professor")
def reservation_history():
    db = get_db()
    reservations = db.execute(
        """
        SELECT
            r.*,
            CASE
                WHEN r.recurso_tipo = 'sala' THEN rooms.nome
                ELSE equipments.nome
            END AS recurso_nome
        FROM reservations r
        LEFT JOIN rooms ON r.recurso_tipo = 'sala' AND rooms.id = r.recurso_id AND rooms.deleted_at IS NULL
        LEFT JOIN equipments ON r.recurso_tipo = 'equipamento' AND equipments.id = r.recurso_id AND equipments.deleted_at IS NULL
        WHERE r.usuario_id = ?
        ORDER BY r.data DESC, r.horario_inicio DESC
        """,
        (g.user["id"],),
    ).fetchall()

    return render_template("reservations/history.html", reservations=reservations)


@bp.route("/reservas/exportar.csv")
@login_required
def export_reservations_csv():
    filter_date = request.args.get("date", "")
    filter_room = request.args.get("room", "")
    filter_teacher = request.args.get("teacher", "")

    filters = {
        "date": filter_date,
        "room_id": int(filter_room) if filter_room.isdigit() else None,
        "teacher_id": int(filter_teacher) if filter_teacher.isdigit() else None,
    }

    rows = get_reservations(filters)
    data_rows = [
        [
            row["id"],
            row["data"],
            row["horario_inicio"],
            row["horario_fim"],
            row["recurso_tipo"],
            row["recurso_nome"] or "Removido",
            row["professor_nome"],
            row["observacao"] or "",
        ]
        for row in rows
    ]
    return build_csv_response(
        "reservas.csv",
        ["id", "data", "inicio", "fim", "recurso_tipo", "recurso_nome", "professor", "observacao"],
        data_rows,
    )


@bp.route("/admin/usuarios", methods=("GET", "POST"))
@roles_required("admin")
def admin_users():
    db = get_db()
    role_filter = request.args.get("tipo", "todos").strip().lower()
    search = request.args.get("busca", "").strip()
    sort_by = request.args.get("ordem", "nome")
    page = request.args.get("pagina", type=int, default=1)
    per_page = 10

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        tipo = request.form.get("tipo", "")
        force_change = 1 if request.form.get("troca_forcada") == "on" else 0

        error = None
        if not nome or not email or not senha:
            error = "Preencha nome, email e senha."
        elif tipo not in {"professor", "aluno", "admin"}:
            error = "Tipo de usuário inválido."
        elif not is_strong_password(senha):
            error = "Senha fraca: use 8+ caracteres com maiúscula, minúscula, número e símbolo."
        elif db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            error = "Já existe usuário com esse email."

        if error is None:
            db.execute(
                "INSERT INTO users (nome, email, senha_hash, tipo, must_change_password) VALUES (?, ?, ?, ?, ?)",
                (nome, email, generate_password_hash(senha), tipo, force_change),
            )
            db.commit()
            log_action(
                "usuario_criado",
                f"Admin criou usuário {email} ({tipo})",
                after={"nome": nome, "email": email, "tipo": tipo, "must_change_password": force_change},
            )
            flash("Usuário criado com sucesso.", "success")
            return redirect(url_for("main.admin_users", tipo=role_filter, busca=search, ordem=sort_by, pagina=page))

        flash(error, "error")

    if role_filter not in {"todos", "admin", "professor", "aluno"}:
        role_filter = "todos"
    if sort_by not in {"nome", "tipo", "created_at"}:
        sort_by = "nome"

    where_clauses = []
    params = []
    where_clauses.append("deleted_at IS NULL")
    if role_filter != "todos":
        where_clauses.append("tipo = ?")
        params.append(role_filter)
    if search:
        where_clauses.append("(LOWER(nome) LIKE ? OR LOWER(email) LIKE ?)")
        term = f"%{search.lower()}%"
        params.extend([term, term])

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    users_all = db.execute(
        f"SELECT id, nome, email, tipo, created_at FROM users {where_sql} ORDER BY {sort_by}, nome",
        params,
    ).fetchall()
    users, pagination = paginate(users_all, page, per_page)

    count_rows = db.execute(
        """
        SELECT tipo, COUNT(*) AS total
        FROM users
        WHERE deleted_at IS NULL
        GROUP BY tipo
        """
    ).fetchall()
    counts = {"admin": 0, "professor": 0, "aluno": 0}
    for row in count_rows:
        counts[row["tipo"]] = row["total"]
    counts["todos"] = counts["admin"] + counts["professor"] + counts["aluno"]

    return render_template(
        "admin/users.html",
        users=users,
        sort_by=sort_by,
        pagination=pagination,
        role_filter=role_filter,
        search=search,
        counts=counts,
    )


@bp.route("/admin/usuarios/<int:user_id>/remover", methods=("POST",))
@roles_required("admin")
def admin_delete_user(user_id):
    db = get_db()
    role_filter = request.form.get("tipo", "todos")
    search = request.form.get("busca", "")
    sort_by = request.form.get("ordem", "nome")
    page = request.form.get("pagina", "1")
    user = db.execute("SELECT id, email FROM users WHERE id = ?", (user_id,)).fetchone()

    if user is None:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("main.admin_users", tipo=role_filter, busca=search))

    if user["id"] == g.user["id"]:
        flash("Você não pode remover sua própria conta.", "error")
        return redirect(url_for("main.admin_users", tipo=role_filter, busca=search))

    before = dict(user)
    archived_email = f"{user['email']}#deleted#{user_id}"
    db.execute(
        """
        UPDATE users
        SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP, email = ?
        WHERE id = ?
        """,
        (archived_email, user_id),
    )
    db.commit()
    log_action("usuario_removido", f"Admin removeu usuário {user['email']}", before=before, after={"deleted_at": "set"})
    flash("Usuário removido.", "success")
    return redirect(url_for("main.admin_users", tipo=role_filter, busca=search, ordem=sort_by, pagina=page))


@bp.route("/admin/recursos", methods=("GET", "POST"))
@roles_required("admin")
def admin_resources():
    db = get_db()
    action = request.form.get("action")

    if request.method == "POST":
        if action == "create_room":
            nome = request.form.get("nome", "").strip()
            capacidade = request.form.get("capacidade", "0").strip()
            descricao = request.form.get("descricao", "").strip()

            if not nome or not capacidade.isdigit() or int(capacidade) <= 0:
                flash("Dados da sala inválidos.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO rooms (nome, capacidade, descricao) VALUES (?, ?, ?)",
                        (nome, int(capacidade), descricao),
                    )
                    db.commit()
                    log_action("sala_criada", f"Sala {nome} cadastrada", after={"nome": nome, "capacidade": int(capacidade)})
                    flash("Sala cadastrada com sucesso.", "success")
                except sqlite3.IntegrityError:
                    flash("Já existe sala com esse nome.", "error")

        elif action == "create_equipment":
            nome = request.form.get("nome", "").strip()
            descricao = request.form.get("descricao", "").strip()
            disponivel = 1 if request.form.get("disponivel") == "on" else 0

            if not nome:
                flash("Nome do equipamento é obrigatório.", "error")
            else:
                try:
                    db.execute(
                        "INSERT INTO equipments (nome, descricao, disponivel) VALUES (?, ?, ?)",
                        (nome, descricao, disponivel),
                    )
                    db.commit()
                    log_action("equipamento_criado", f"Equipamento {nome} cadastrado", after={"nome": nome, "disponivel": disponivel})
                    flash("Equipamento cadastrado com sucesso.", "success")
                except sqlite3.IntegrityError:
                    flash("Já existe equipamento com esse nome.", "error")

        return redirect(url_for("main.admin_resources"))

    rooms = db.execute("SELECT * FROM rooms WHERE deleted_at IS NULL ORDER BY nome").fetchall()
    equipments = db.execute("SELECT * FROM equipments WHERE deleted_at IS NULL ORDER BY nome").fetchall()
    return render_template("admin/resources.html", rooms=rooms, equipments=equipments)


@bp.route("/admin/salas/<int:room_id>/editar", methods=("POST",))
@roles_required("admin")
def admin_edit_room(room_id):
    db = get_db()
    before_row = db.execute("SELECT * FROM rooms WHERE id = ? AND deleted_at IS NULL", (room_id,)).fetchone()
    if before_row is None:
        flash("Sala não encontrada.", "error")
        return redirect(url_for("main.admin_resources"))
    nome = request.form.get("nome", "").strip()
    capacidade = request.form.get("capacidade", "0").strip()
    descricao = request.form.get("descricao", "").strip()

    if not nome or not capacidade.isdigit() or int(capacidade) <= 0:
        flash("Dados da sala inválidos.", "error")
        return redirect(url_for("main.admin_resources"))

    try:
        db.execute(
            "UPDATE rooms SET nome = ?, capacidade = ?, descricao = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (nome, int(capacidade), descricao, room_id),
        )
        db.commit()
        log_action(
            "sala_editada",
            f"Sala #{room_id} atualizada",
            before={"nome": before_row["nome"], "capacidade": before_row["capacidade"], "descricao": before_row["descricao"]},
            after={"nome": nome, "capacidade": int(capacidade), "descricao": descricao},
        )
        flash("Sala atualizada.", "success")
    except sqlite3.IntegrityError:
        flash("Já existe sala com esse nome.", "error")

    return redirect(url_for("main.admin_resources"))


@bp.route("/admin/salas/<int:room_id>/remover", methods=("POST",))
@roles_required("admin")
def admin_delete_room(room_id):
    db = get_db()
    room = db.execute("SELECT id, nome FROM rooms WHERE id = ? AND deleted_at IS NULL", (room_id,)).fetchone()
    if room is None:
        flash("Sala não encontrada.", "error")
        return redirect(url_for("main.admin_resources"))
    archived_name = f"{room['nome']}#deleted#{room_id}"
    db.execute(
        """
        UPDATE rooms
        SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP, nome = ?
        WHERE id = ?
        """,
        (archived_name, room_id),
    )
    db.commit()
    log_action("sala_removida", f"Sala #{room_id} removida", before={"id": room["id"], "nome": room["nome"]}, after={"deleted": True})
    flash("Sala removida.", "success")
    return redirect(url_for("main.admin_resources"))


@bp.route("/admin/equipamentos/<int:equipment_id>/editar", methods=("POST",))
@roles_required("admin")
def admin_edit_equipment(equipment_id):
    db = get_db()
    before_row = db.execute("SELECT * FROM equipments WHERE id = ? AND deleted_at IS NULL", (equipment_id,)).fetchone()
    if before_row is None:
        flash("Equipamento não encontrado.", "error")
        return redirect(url_for("main.admin_resources"))
    nome = request.form.get("nome", "").strip()
    descricao = request.form.get("descricao", "").strip()
    disponivel = 1 if request.form.get("disponivel") == "on" else 0

    if not nome:
        flash("Nome do equipamento é obrigatório.", "error")
        return redirect(url_for("main.admin_resources"))

    try:
        db.execute(
            "UPDATE equipments SET nome = ?, descricao = ?, disponivel = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (nome, descricao, disponivel, equipment_id),
        )
        db.commit()
        log_action(
            "equipamento_editado",
            f"Equipamento #{equipment_id} atualizado",
            before={"nome": before_row["nome"], "descricao": before_row["descricao"], "disponivel": before_row["disponivel"]},
            after={"nome": nome, "descricao": descricao, "disponivel": disponivel},
        )
        flash("Equipamento atualizado.", "success")
    except sqlite3.IntegrityError:
        flash("Já existe equipamento com esse nome.", "error")

    return redirect(url_for("main.admin_resources"))


@bp.route("/admin/equipamentos/<int:equipment_id>/remover", methods=("POST",))
@roles_required("admin")
def admin_delete_equipment(equipment_id):
    db = get_db()
    equipment = db.execute("SELECT id, nome FROM equipments WHERE id = ? AND deleted_at IS NULL", (equipment_id,)).fetchone()
    if equipment is None:
        flash("Equipamento não encontrado.", "error")
        return redirect(url_for("main.admin_resources"))
    archived_name = f"{equipment['nome']}#deleted#{equipment_id}"
    db.execute(
        """
        UPDATE equipments
        SET deleted_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP, nome = ?
        WHERE id = ?
        """,
        (archived_name, equipment_id),
    )
    db.commit()
    log_action(
        "equipamento_removido",
        f"Equipamento #{equipment_id} removido",
        before={"id": equipment["id"], "nome": equipment["nome"]},
        after={"deleted": True},
    )
    flash("Equipamento removido.", "success")
    return redirect(url_for("main.admin_resources"))


@bp.route("/admin/reservas")
@roles_required("admin")
def admin_reservations():
    page = request.args.get("pagina", type=int, default=1)
    reservations_all = get_reservations()
    reservations, pagination = paginate(reservations_all, page, 12)
    return render_template("admin/reservations.html", reservations=reservations, pagination=pagination)


@bp.route("/admin/relatorios")
@roles_required("admin")
def admin_reports():
    db = get_db()
    page = request.args.get("pagina", type=int, default=1)
    per_page = 20

    room_usage = db.execute(
        """
        SELECT rooms.nome, COUNT(*) AS total
        FROM reservations r
        JOIN rooms ON r.recurso_tipo = 'sala' AND rooms.id = r.recurso_id
        GROUP BY rooms.id
        ORDER BY total DESC, rooms.nome
        """
    ).fetchall()

    equipment_usage = db.execute(
        """
        SELECT equipments.nome, COUNT(*) AS total
        FROM reservations r
        JOIN equipments ON r.recurso_tipo = 'equipamento' AND equipments.id = r.recurso_id
        GROUP BY equipments.id
        ORDER BY total DESC, equipments.nome
        """
    ).fetchall()

    teacher_usage = db.execute(
        """
        SELECT users.nome, COUNT(*) AS total
        FROM reservations r
        JOIN users ON users.id = r.usuario_id
        GROUP BY users.id
        ORDER BY total DESC, users.nome
        """
    ).fetchall()

    logs_all = db.execute(
        """
        SELECT l.*, u.nome AS user_nome
        FROM activity_logs l
        LEFT JOIN users u ON u.id = l.user_id
        ORDER BY l.created_at DESC
        """
    ).fetchall()
    logs, logs_pagination = paginate(logs_all, page, per_page)

    return render_template(
        "admin/reports.html",
        room_usage=room_usage,
        equipment_usage=equipment_usage,
        teacher_usage=teacher_usage,
        logs=logs,
        room_usage_json=[{"nome": row["nome"], "total": row["total"]} for row in room_usage],
        equipment_usage_json=[{"nome": row["nome"], "total": row["total"]} for row in equipment_usage],
        teacher_usage_json=[{"nome": row["nome"], "total": row["total"]} for row in teacher_usage],
        logs_pagination=logs_pagination,
    )


@bp.route("/admin/relatorios/exportar/<string:report_type>.csv")
@roles_required("admin")
def admin_export_reports(report_type):
    db = get_db()

    if report_type == "salas":
        rows = db.execute(
            """
            SELECT rooms.nome AS nome, COUNT(*) AS total
            FROM reservations r
            JOIN rooms ON r.recurso_tipo = 'sala' AND rooms.id = r.recurso_id
            GROUP BY rooms.id
            ORDER BY total DESC, rooms.nome
            """
        ).fetchall()
        filename = "relatorio_salas.csv"
    elif report_type == "equipamentos":
        rows = db.execute(
            """
            SELECT equipments.nome AS nome, COUNT(*) AS total
            FROM reservations r
            JOIN equipments ON r.recurso_tipo = 'equipamento' AND equipments.id = r.recurso_id
            GROUP BY equipments.id
            ORDER BY total DESC, equipments.nome
            """
        ).fetchall()
        filename = "relatorio_equipamentos.csv"
    elif report_type == "professores":
        rows = db.execute(
            """
            SELECT users.nome AS nome, COUNT(*) AS total
            FROM reservations r
            JOIN users ON users.id = r.usuario_id
            GROUP BY users.id
            ORDER BY total DESC, users.nome
            """
        ).fetchall()
        filename = "relatorio_professores.csv"
    else:
        return Response("Tipo de relatório inválido.", status=400, mimetype="text/plain")

    data_rows = [[row["nome"], row["total"]] for row in rows]
    return build_csv_response(filename, ["nome", "total_reservas"], data_rows)






