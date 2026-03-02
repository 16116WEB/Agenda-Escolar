import sqlite3
from pathlib import Path
from typing import Any

from flask import current_app, g


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = Path(current_app.config.get("DATABASE", Path(current_app.instance_path) / "agenda_escola.db"))
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_: Any = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    schema_path = Path(current_app.root_path) / "schema.sql"
    db.executescript(schema_path.read_text(encoding="utf-8"))
    db.commit()


def seed_admin() -> None:
    from werkzeug.security import generate_password_hash

    db = get_db()
    admin_email = "admin@escola.local"
    exists = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()

    if exists:
        return

    db.execute(
        """
        INSERT INTO users (nome, email, senha_hash, tipo, must_change_password)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "Administrador",
            admin_email,
            generate_password_hash("admin123"),
            "admin",
            1,
        ),
    )
    db.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        """Inicializa o banco de dados e cria o admin padrão."""
        init_db()
        seed_admin()
        print("Banco inicializado com sucesso.")
        print("Admin padrão: admin@escola.local | senha: admin123")

    @app.cli.command("seed-demo")
    def seed_demo_command():
        """Cria dados de demonstração (usuários, recursos e reservas)."""
        from werkzeug.security import generate_password_hash

        db = get_db()
        users = [
            ("Ana Professora", "ana.prof@escola.local", "professor"),
            ("Carlos Professor", "carlos.prof@escola.local", "professor"),
            ("Bianca Aluna", "bianca.aluno@escola.local", "aluno"),
            ("Diego Aluno", "diego.aluno@escola.local", "aluno"),
        ]
        for nome, email, tipo in users:
            exists = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if not exists:
                db.execute(
                    "INSERT INTO users (nome, email, senha_hash, tipo) VALUES (?, ?, ?, ?)",
                    (nome, email, generate_password_hash("123456"), tipo),
                )

        rooms = [
            ("Laboratório de Informática", 30, "Sala com computadores e projetor."),
            ("Sala 201", 35, "Sala padrão para aulas teóricas."),
            ("Auditório", 120, "Espaço para palestras e apresentações."),
        ]
        for nome, capacidade, descricao in rooms:
            exists = db.execute("SELECT id FROM rooms WHERE nome = ?", (nome,)).fetchone()
            if not exists:
                db.execute("INSERT INTO rooms (nome, capacidade, descricao) VALUES (?, ?, ?)", (nome, capacidade, descricao))

        equipments = [
            ("Projetor Epson", "Projetor multimídia HD", 1),
            ("Kit Robótica", "Conjunto com Arduino e sensores", 1),
            ("Caixa de Som", "Som portátil para apresentações", 1),
        ]
        for nome, descricao, disponivel in equipments:
            exists = db.execute("SELECT id FROM equipments WHERE nome = ?", (nome,)).fetchone()
            if not exists:
                db.execute(
                    "INSERT INTO equipments (nome, descricao, disponivel) VALUES (?, ?, ?)",
                    (nome, descricao, disponivel),
                )

        prof_ana = db.execute("SELECT id FROM users WHERE email = 'ana.prof@escola.local'").fetchone()
        prof_carlos = db.execute("SELECT id FROM users WHERE email = 'carlos.prof@escola.local'").fetchone()
        lab = db.execute("SELECT id FROM rooms WHERE nome = 'Laboratório de Informática'").fetchone()
        sala201 = db.execute("SELECT id FROM rooms WHERE nome = 'Sala 201'").fetchone()
        projetor = db.execute("SELECT id FROM equipments WHERE nome = 'Projetor Epson'").fetchone()

        demo_reservations = [
            (prof_ana["id"], "sala", lab["id"], "2026-03-02", "08:00", "09:40", "Aula prática de programação."),
            (prof_carlos["id"], "sala", sala201["id"], "2026-03-02", "10:00", "11:40", "Revisão para prova."),
            (prof_ana["id"], "equipamento", projetor["id"], "2026-03-03", "13:00", "14:30", "Apresentação de slides."),
        ]
        for item in demo_reservations:
            exists = db.execute(
                """
                SELECT id FROM reservations
                WHERE usuario_id = ? AND recurso_tipo = ? AND recurso_id = ? AND data = ? AND horario_inicio = ? AND horario_fim = ?
                """,
                item[:6],
            ).fetchone()
            if not exists:
                db.execute(
                    """
                    INSERT INTO reservations (usuario_id, recurso_tipo, recurso_id, data, horario_inicio, horario_fim, observacao)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    item,
                )

        db.commit()
        print("Dados de demonstração criados/atualizados.")
        print("Login professor demo: ana.prof@escola.local / 123456")
