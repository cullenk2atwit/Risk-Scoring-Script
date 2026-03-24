import hashlib
import requests
import math
import getpass

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
OFFLINE_FILE = "rockyou.txt"


def calculate_entropy(password):
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() for c in password): pool += 32

    if pool == 0:
        return 0
    return len(password) * math.log2(pool)



# ONLINE CHECK (HIBP)
def check_pwned_online(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            HIBP_API_URL + prefix,
            headers={"User-Agent": "PasswordChecker"},
            timeout=5
        )

        # RATE LIMIT
        if response.status_code == 429:
            print("[INFO] API rate limited. Switching to offline mode.")
            return None

        if response.status_code != 200:
            print(f"[INFO] API error ({response.status_code}). Using offline mode.")
            return None

        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)

        return 0

    except Exception:
        print("[INFO] API request failed. Using offline mode.")
        return None



# OFFLINE CHECK
def check_pwned_offline(password):
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        suffix = sha1[5:]

        with open(OFFLINE_FILE, "r") as f:
            for line in f:
                h, count = line.strip().split(":")
                if h == suffix:
                    return int(count)

        return 0

    except FileNotFoundError:
        print("[WARNING] Offline hash file not found.")
        return 0



# HASH GENERATION
def generate_hashes(password):
    return {
        "MD5": hashlib.md5(password.encode()).hexdigest(),
        "SHA1": hashlib.sha1(password.encode()).hexdigest(),
        "SHA256": hashlib.sha256(password.encode()).hexdigest(),
        "SHA512": hashlib.sha512(password.encode()).hexdigest()
    }


# MAIN STRENGTH CHECK
def check_password_strength(password):
    score = 0
    feedback = []

    # LENGTH
    length = len(password)
    if length < 8:
        return 0, "Very Weak", ["Too short"], 0

    elif length >= 20:
        score += 60
        feedback.append("Excellent length (20+)")
    elif length >= 15:
        score += 50
        feedback.append("Strong length (15+)")
    else:
        score += 30
        feedback.append("Acceptable length (8–14)")

    # CHARACTER TYPES
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    diversity = sum([has_lower, has_upper, has_digit, has_symbol])

    if diversity >= 3:
        score += 20
        feedback.append("Good character variety")
    elif diversity == 2:
        score += 10
        feedback.append("Moderate character variety")
    else:
        feedback.append("Low character variety")

    if has_symbol:
        score += 10
        feedback.append("Includes special characters")

    if " " in password:
        score += 10
        feedback.append("Passphrase detected")

    # ENTROPY
    entropy = calculate_entropy(password)
    if entropy > 60:
        score += 20
        feedback.append("High entropy")
    elif entropy > 40:
        score += 10
        feedback.append("Moderate entropy")

    # BREACH CHECK (ONLINE / OFFLINE)
    breach_count = check_pwned_online(password)

    if breach_count is None:
        breach_count = check_pwned_offline(password)

    if breach_count > 0:
        score -= 50
        feedback.append(f"Found in breach database ({breach_count} times)")

    score = max(0, min(score, 100))

    # LABEL
    if score >= 85:
        strength = "Strong"
    elif score >= 65:
        strength = "Moderate"
    elif score >= 40:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return score, strength, feedback, breach_count


# MAIN PROGRAM
if __name__ == "__main__":
    print("Password Strength Checker\n")

    password = getpass.getpass("Enter password: ")

    score, strength, feedback, breaches = check_password_strength(password)
    hashes = generate_hashes(password)

    print("\n--- RESULTS ---")
    print(f"Score: {score}/100")
    print(f"Strength: {strength}")
    print(f"Breach Count: {breaches}")

    print("\nFeedback:")
    for f in feedback:
        print(f" - {f}")

    print("\nHashes:")
    for k, v in hashes.items():
        print(f"{k}: {v}")