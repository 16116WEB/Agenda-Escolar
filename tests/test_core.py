from werkzeug.security import generate_password_hash


def login(client, email, password):
    token = "test-token"
    with client.session_transaction() as sess:
        sess["csrf_token"] = token
    return client.post("/login", data={"email": email, "password": password, "csrf_token": token}, follow_redirects=False)


def test_login_rate_limit(client):
    for _ in range(5):
        response = login(client, "naoexiste@test.local", "senhaerrada")
        assert response.status_code == 200

    response = login(client, "naoexiste@test.local", "senhaerrada")
    assert b"Muitas tentativas" in response.data


def test_student_cannot_create_reservation(app_instance, client):
    with app_instance.app_context():
        from app.db import get_db

        db = get_db()
        db.execute(
            "INSERT INTO users (nome, email, senha_hash, tipo, must_change_password) VALUES (?, ?, ?, ?, 0)",
            ("Aluno T", "aluno@test.local", generate_password_hash("Test@1234"), "aluno"),
        )
        db.commit()

    login(client, "aluno@test.local", "Test@1234")
    response = client.get("/reservas/nova", follow_redirects=False)
    assert response.status_code == 302


def test_conflict_reservation_blocked(app_instance, client):
    room_id = None
    with app_instance.app_context():
        from app.db import get_db

        db = get_db()
        prof = db.execute("SELECT id FROM users WHERE email='prof@test.local'").fetchone()
        room = db.execute("SELECT id FROM rooms WHERE nome='Sala T1'").fetchone()
        room_id = room["id"]

        db.execute(
            """
            INSERT INTO reservations (usuario_id, recurso_tipo, recurso_id, data, horario_inicio, horario_fim, observacao)
            VALUES (?, 'sala', ?, '2026-03-10', '08:00', '09:00', 'Primeira reserva')
            """,
            (prof["id"], room_id),
        )
        db.commit()

    login(client, "prof@test.local", "Test@1234")
    with client.session_transaction() as sess:
        token = sess["csrf_token"]
    response = client.post(
        "/reservas/nova",
        data={
            "csrf_token": token,
            "resource_type": "sala",
            "resource_id": str(room_id),
            "date": "2026-03-10",
            "start_time": "08:30",
            "end_time": "09:30",
            "observacao": "Conflito",
        },
        follow_redirects=True,
    )
    assert b"Conflito de hor" in response.data


def test_password_policy_in_admin_create_user(app_instance, client):
    login(client, "admin@escola.local", "admin123")

    with client.session_transaction() as sess:
        token = sess["csrf_token"]

    response = client.post(
        "/admin/usuarios",
        data={
            "csrf_token": token,
            "nome": "Novo User",
            "email": "novo@teste.local",
            "senha": "123456",
            "tipo": "professor",
        },
        follow_redirects=True,
    )
    assert b"Senha fraca" in response.data
