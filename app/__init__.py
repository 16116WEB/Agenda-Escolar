from datetime import timedelta
import os
from pathlib import Path

from flask import Flask, session

from . import db
from .views import bp


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("AGENDA_SECRET_KEY", "dev"),
        DATABASE=Path(app.instance_path) / "agenda_escola.db",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=45),
        SECURITY_MAX_LOGIN_ATTEMPTS=5,
        SECURITY_LOGIN_WINDOW_MINUTES=15,
        RESERVATION_START_HOUR=7,
        RESERVATION_END_HOUR=22,
        RESERVATION_MAX_MINUTES=240,
    )

    if test_config is None:
        app.config.from_pyfile("config.py", silent=True)
    else:
        app.config.update(test_config)

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    app.register_blueprint(bp)

    @app.context_processor
    def inject_security_helpers():
        import secrets

        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(24)
            session["csrf_token"] = token
        return {"csrf_token": token}

    return app
