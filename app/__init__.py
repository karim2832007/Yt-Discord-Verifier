from flask import Flask
from flask_cors import CORS
from app.extensions import db

def create_app():
    app = Flask(__name__, static_folder="static")

    # Load config
    app.config.from_object("app.config.Config")

    # Enable CORS
    CORS(app)

    # Initialize SQLAlchemy
    db.init_app(app)

    # -------------------------
    # Import Blueprints
    # -------------------------
    from app.routes.verifier_routes import bp as verifier_bp
    from app.routes.auth_routes import bp as auth_bp
    from app.routes.discord_routes import bp as discord_bp
    from app.routes.user_routes import bp as user_bp
    from app.routes.key_routes import bp as key_bp
    from app.routes.game_routes import bp as game_bp
    from app.routes.nsfw_routes import bp as nsfw_bp
    from app.routes.admin_routes import bp as admin_bp
    from app.routes.system_routes import bp as system_bp
    from app.routes.lootlabs_routes import bp as lootlabs_bp
    from app.routes.redeem_routes import bp as redeem_bp
    from app.routes.key_info_routes import bp as key_info_bp
    from app.routes.key_admin_routes import bp as key_admin_bp

    # -------------------------
    # Register Blueprints
    # -------------------------
    app.register_blueprint(key_bp, url_prefix="/key")
    app.register_blueprint(verifier_bp)
    app.register_blueprint(redeem_bp)
    app.register_blueprint(key_info_bp)
    app.register_blueprint(key_admin_bp)

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(discord_bp, url_prefix="/discord")
    app.register_blueprint(user_bp, url_prefix="/user")
    app.register_blueprint(game_bp, url_prefix="/games")
    app.register_blueprint(nsfw_bp, url_prefix="/nsfw")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(system_bp, url_prefix="/system")
    app.register_blueprint(lootlabs_bp, url_prefix="/lootlabs")

    # -------------------------
    # Serve favicon
    # -------------------------
    @app.route("/favicon.svg")
    def favicon():
        return app.send_static_file("favicon.svg")

    # -------------------------
    # CREATE TABLES
    # -------------------------
    with app.app_context():
        # Import ALL models so SQLAlchemy knows them
        from app.models.user import User
        from app.models.device import Device
        from app.models.key import Key
        from app.models.perks import Perk
        from app.models.nsfw import NSFWToken
        from app.models.admin import AdminLog
        from app.models.game import Game
        from app.models.game_download_link import GameDownloadLink  # NEW

        db.create_all()

    return app
