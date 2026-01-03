from flask import jsonify, request
import json
import logging


def register_error_handlers(app):
    """
    Registers global error handlers for HTTP errors and unexpected exceptions.
    """

    @app.errorhandler(400)
    def bad_request(err):
        payload = {"ok": False, "error": "bad_request", "message": str(err)}
        app.logger_custom.warning(json.dumps({"event": "http.400", "message": str(err)}))
        return jsonify(payload), 400

    @app.errorhandler(404)
    def not_found(err):
        payload = {"ok": False, "error": "not_found", "message": "not found"}
        app.logger_custom.warning(json.dumps({"event": "http.404", "path": request.path}))
        return jsonify(payload), 404

    @app.errorhandler(Exception)
    def handle_exception(exc):
        app.logger_custom.exception(json.dumps({
            "event": "exception",
            "exception": repr(exc),
            "path": request.path,
            "method": request.method
        }))
        payload = {
            "ok": False,
            "error": "internal_error",
            "message": "internal server error"
        }
        return jsonify(payload), 500