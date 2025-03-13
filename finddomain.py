import random
import time
import whois  # pip install python-whois

def generate_domain():
    # Allowed characters: letters (a-z), digits (0-9) and hyphen (only in middle positions)
    allowed_first = 'abcdefghijklmnopqrstuvwxyz0123456789'
    allowed_mid = allowed_first + '-'  # hyphen allowed in positions 2 and 3
    allowed_last = allowed_first

    domain = random.choice(allowed_first) \
             + random.choice(allowed_mid) \
             + random.choice(allowed_mid) \
             + random.choice(allowed_last)
    return domain + '.com'

def is_available(domain):
    try:
        result = whois.whois(domain)
        # If the WHOIS result does not contain a domain name, it might be available.
        if result.domain_name is None:
            return True
        return False
    except Exception as e:
        # Exceptions often indicate that the domain is not registered (or there's a lookup issue).
        return True

if __name__ == '__main__':
    attempts = 0
    max_attempts = 200  # Adjust as needed
    found = False

    while not found and attempts < max_attempts:
        d = generate_domain()
        print(f"Checking {d}...")
        if is_available(d):
            print(f"Found available domain: {d}")
            found = True
        else:
            print(f"{d} is taken.")
        attempts += 1
        time.sleep(1)  # Pause to avoid rate limiting

    if not found:
        print("No available domain found in the given attempts. Try increasing the attempt count or refine your strategy.")

