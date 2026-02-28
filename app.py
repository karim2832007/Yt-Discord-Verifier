from flask import Flask
from routes.validate_routes import validate_bp
from routes.discord_routes import discord_bp

def start_api():
    app = Flask(__name__)

    app.register_blueprint(validate_bp)
    app.register_blueprint(discord_bp, url_prefix="/discord")

    print("[API] Running on port 5000")
    app.run(host="0.0.0.0", port=5000)
