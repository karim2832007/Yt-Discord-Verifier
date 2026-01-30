from app.extensions import db

class GameDownloadLink(db.Model):
    __tablename__ = "game_download_links"

    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey("games.id"), nullable=False)

    # Label shown to the user (e.g., "Mega", "Google Drive", "Direct Link")
    label = db.Column(db.String, nullable=False)

    # URL for remote links OR public URL for local files
    url = db.Column(db.String, nullable=False)

    # If true → file was uploaded via SFTP
    is_local = db.Column(db.Boolean, default=False)

    # Path on your IONOS server (optional)
    file_path = db.Column(db.String, nullable=True)
