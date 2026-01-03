from flask import jsonify
import json


# -----------------------------
# Custom Exceptions
# -----------------------------

class ValidationError(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors or []


class AuthorizationError(Exception):
    pass


class NotFoundError(Exception):
    pass


# -----------------------------
# Global Exception Handlers
# -----------------------------

def register_exception_handlers(app):
    """
    Registers global exception handlers for ValidationError,
    AuthorizationError, and NotFoundError.
    """

    @app.errorhandler(ValidationError)
    def handle_validation(err):
        app.logger_custom.warning(json.dumps({
            "event": "validation_error",
            "message": str(err),
            "errors": getattr(err, "errors", [])
        }))
        return jsonify({
            "ok": False,
            "error": "validation_error",
            "message": str(err)
        }), 400

    @app.errorhandler(AuthorizationError)
    def handle_auth(err):
        app.logger_custom.warning(json.dumps({
            "event": "auth_error",
            "message": str(err)
        }))
        return jsonify({
            "ok": False,
            "error": "forbidden",
            "message": "not authorized"
        }), 403

    @app.errorhandler(NotFoundError)
    def handle_not_found(err):
        app.logger_custom.warning(json.dumps({
            "event": "not_found",
            "message": str(err)
        }))
        return jsonify({
            "ok": False,
            "error": "not_found",
            "message": str(err)
        }), 404