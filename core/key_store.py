import mysql.connector
import time

# Admin override duration (same as old system)
LEGACY_LIMIT_SECONDS = 86400 # 24 hours
# -----------------------------------------
# DATABASE CONNECTION (matches your PHP DB)
# -----------------------------------------
def get_db():
    return mysql.connector.connect(
        host="82.165.136.190",
        user="phpuser",
        password="Kmrykmry@4",
        database="gaming_mods"
    )

# -----------------------------------------
# FETCH KEY FROM MYSQL
# -----------------------------------------
def _get_key_from_store(key_value):
    db = get_db()
    cursor = db.cursor(dictionary=True)

    cursor.execute("""
        SELECT 
            key_value,
            expires_at,
            status,
            created_ip,
            duration_minutes,
            expiry_iso,
            user_id,
            type
        FROM generated_keys
        WHERE key_value = %s
        LIMIT 1
    """, (key_value,))

    record = cursor.fetchone()

    cursor.close()
    db.close()

    return record

# -----------------------------------------
# BURN KEY (mark as burned)
# -----------------------------------------
def burn_key(key_value):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        UPDATE generated_keys
        SET status = 'burned'
        WHERE key_value = %s
    """, (key_value,))

    db.commit()
    cursor.close()
    db.close()
