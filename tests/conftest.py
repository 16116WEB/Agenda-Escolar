import tempfile
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

from app import create_app
from app.db import get_db, init_db, seed_admin


@pytest.fixture
def app_instance():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test",
                "DATABASE": db_path,
                "PERMANENT_SESSION_LIFETIME": __import__("datetime").timedelta(minutes=45),
            }
        )

        with app.app_context():
            init_db()
            seed_admin()
            db = get_db()
            db.execute("UPDATE users SET must_change_password = 0 WHERE email = 'admin@escola.local'")
            db.execute(
                "INSERT INTO users (nome, email, senha_hash, tipo, must_change_password) VALUES (?, ?, ?, ?, 0)",
                ("Prof Teste", "prof@test.local", generate_password_hash("Test@1234"), "professor"),
            )
            db.execute("INSERT INTO rooms (nome, capacidade, descricao) VALUES (?, ?, ?)", ("Sala T1", 20, "Teste"))
            db.commit()

        yield app


@pytest.fixture
def client(app_instance):
    return app_instance.test_client()


def csrf(client):
    with client.session_transaction() as sess:
        sess["csrf_token"] = "test-token"
    return "test-token"
