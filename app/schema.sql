DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS reservations;
DROP TABLE IF EXISTS equipments;
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    tipo TEXT NOT NULL CHECK (tipo IN ('professor', 'aluno', 'admin')),
    must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL UNIQUE,
    capacidade INTEGER NOT NULL CHECK (capacidade > 0),
    descricao TEXT DEFAULT '',
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE equipments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL UNIQUE,
    descricao TEXT DEFAULT '',
    disponivel INTEGER NOT NULL DEFAULT 1 CHECK (disponivel IN (0, 1)),
    deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    recurso_tipo TEXT NOT NULL CHECK (recurso_tipo IN ('sala', 'equipamento')),
    recurso_id INTEGER NOT NULL,
    data TEXT NOT NULL,
    horario_inicio TEXT NOT NULL,
    horario_fim TEXT NOT NULL,
    observacao TEXT DEFAULT '',
    data_criacao TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_atualizacao TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES users (id)
);

CREATE TABLE activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    acao TEXT NOT NULL,
    detalhes TEXT NOT NULL,
    ip_origem TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    payload_before TEXT DEFAULT '',
    payload_after TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip_origem TEXT NOT NULL,
    sucesso INTEGER NOT NULL CHECK (sucesso IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_active ON users (deleted_at, tipo, nome);
CREATE INDEX idx_rooms_active ON rooms (deleted_at, nome);
CREATE INDEX idx_equipments_active ON equipments (deleted_at, nome);
CREATE INDEX idx_reservations_data ON reservations (data);
CREATE INDEX idx_reservations_resource_slot ON reservations (recurso_tipo, recurso_id, data, horario_inicio, horario_fim);
CREATE INDEX idx_reservations_user ON reservations (usuario_id, data);
CREATE INDEX idx_logs_created_at ON activity_logs (created_at);
CREATE INDEX idx_login_attempts_identity ON login_attempts (email, ip_origem, created_at);
