from flask import Flask, request, g, jsonify, make_response
from flask_cors import CORS
import uuid
import json
import logging

from .config import Config
from .logger import make_logger
from .middleware import register_error_handlers


def create_app(config: Config = None) -> Flask:
    cfg = config or Config()
    app = Flask(__name__)

    # Base config
    app.config.from_mapping(
        SECRET_KEY=cfg.SECRET_KEY,
        DEBUG=cfg.DEBUG,
        ENV=cfg.ENV,
        SESSION_COOKIE_SAMESITE=cfg.SESSION_COOKIE_SAMESITE,
        SESSION_COOKIE_SECURE=cfg.SESSION_COOKIE_SECURE,
        SESSION_COOKIE_DOMAIN=cfg.SESSION_COOKIE_DOMAIN
    )

    # Attach config + logger
    app.cfg = cfg
    logger = make_logger(logfile=cfg.LOG_FILE)
    app.logger_custom = logger

    # CORS
    CORS(app, supports_credentials=True, origins=["https://gaming-mods.com"])

    # OPTIONS handler
    @app.before_request
    def handle_options():
        if request.method == "OPTIONS":
            return make_response("", 200)

    # Request ID
    @app.before_request
    def assign_request_id():
        g.request_id = str(uuid.uuid4())

    # Add request-id filter to logger
    class ReqIdFilter(logging.Filter):
        def filter(self, rec):
            rec.req_id = getattr(g, "request_id", "-")
            return True

    req_filter = ReqIdFilter()
    logger.addFilter(req_filter)
    app.logger.addFilter(req_filter)

    # Register global error handlers
    register_error_handlers(app)

    # Register routes
    from .routes.validate import bp as validate_bp
    from .routes.keys import bp as keys_bp
    from .routes.admin import bp as admin_bp
    from .routes.postback import bp as postback_bp
    from .routes.health import bp as health_bp
    from .routes.oauth import bp as oauth_bp   # <-- ADDED

    app.register_blueprint(validate_bp)
    app.register_blueprint(keys_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(postback_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(oauth_bp)           # <-- ADDED

    return app