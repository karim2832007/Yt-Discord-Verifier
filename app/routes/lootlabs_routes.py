from flask import Blueprint, request, jsonify
from app.services.lootlabs_service import LootLabsService

bp = Blueprint("lootlabs", __name__)

# -----------------------------
# Validate a LootLabs key
# -----------------------------
@bp.post("/validate")
def validate_key():
    data = request.json or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "error": "missing_key"}), 400

    result = LootLabsService.validate_key(key)
    return jsonify(result)


# -----------------------------
# Redeem a LootLabs key
# -----------------------------
@bp.post("/redeem")
def redeem_key():
    data = request.json or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "error": "missing_key"}), 400

    result = LootLabsService.redeem_key(key)
    return jsonify(result)


# -----------------------------
# Generate redirect link
# -----------------------------
@bp.get("/redirect")
def redirect_link():
    redirect_url = request.args.get("redirect_url")
    click_id = request.args.get("click_id")

    if not redirect_url or not click_id:
        return jsonify({"success": False, "error": "missing_parameters"}), 400

    link = LootLabsService.generate_redirect(redirect_url, click_id)
    return jsonify({"success": True, "redirect": link})


# -----------------------------
# LootLabs Postback Handler (FIXED)
# -----------------------------
@bp.post("/postback")
def postback():
    """
    LootLabs will POST data here after a user completes an offer.
    Accepts:
    - form data
    - JSON
    - query parameters
    Required:
    - click_id
    """

    # Accept ALL possible input formats
    data = (
        request.form.to_dict()
        or request.json
        or request.args.to_dict()
        or {}
    )

    # Extract click_id
    click_id = data.get("click_id")

    if not click_id:
        return jsonify({"success": False, "error": "missing_click_id"}), 400

    # Validate postback structure
    result = LootLabsService.verify_postback(data)
    if not result["success"]:
        return jsonify(result), 400

    # TODO: reward logic here
    # Example:
    # user_id = OfferService.get_user_from_click(click_id)
    # OfferService.increment_progress(user_id)
    # if OfferService.is_complete(user_id):
    #     KeyService.create_key(...)

    return jsonify({
        "success": True,
        "message": "Postback received",
        "click_id": click_id,
        "data": data
    }), 200
