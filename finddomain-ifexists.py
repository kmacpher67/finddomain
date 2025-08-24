import random
import time
import whois  # pip install python-whois
import os

def read_domains(filename):
    """Read domains from a file into a set."""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return {line.strip() for line in f if line.strip()}
    return set()

def append_domain(filename, domain):
    """Append a domain to the given file."""
    with open(filename, 'a') as f:
        f.write(domain + "\n")

def generate_domain():
    # Allowed characters:
    # - First and last: letters (a-z) and digits (0-9)
    # - Middle positions: letters (a-z), digits (0-9), and hyphen (-)
    allowed_first = 'abcdefghijklmnopqrstuvwxyz0123456789'
    allowed_mid = allowed_first + '-'  # hyphen allowed in positions 2 and 3
    allowed_last = allowed_first
    domain = (
        random.choice(allowed_first) +
        random.choice(allowed_mid) +
        random.choice(allowed_mid) +
        random.choice(allowed_last)
    )
    return domain + '.com'

def is_available(domain, retries=3):
    """
    Attempts a WHOIS lookup with a retry mechanism.
    Returns True if the domain appears unregistered, False otherwise.
    """
    for attempt in range(retries):
        try:
            result = whois.whois(domain)
            # If the lookup returns nothing or no domain name, treat as available.
            if result is None or result.domain_name is None:
                return True
            return False
        except Exception as e:
            error_message = str(e).lower()
            # If the error message indicates the domain was not found, treat it as available.
            if "no match" in error_message or "not found" in error_message:
                return True
            print(f"Error checking {domain} (attempt {attempt+1}/{retries}): {e}")
            time.sleep(1)  # Wait longer between retries
    print(f"Skipping {domain} after {retries} failed attempts.")
    return False

def main():
    found_file = "found4charcomain.txt"
    taken_file = "taken4domain.txt"

    # Load previously checked domains from files.
    found_domains = read_domains(found_file)
    taken_domains = read_domains(taken_file)

    attempts = 0
    max_attempts = 99999  # Adjust as needed

    while attempts < max_attempts:
        try:
            domain = generate_domain()
            # Skip if this domain was already processed.
            if domain in found_domains or domain in taken_domains:
                print(f"{domain} already checked, skipping.")
                continue
            else:
                time.sleep(1)  # Pause to reduce load / avoid rate limits

            print(f"Checking {domain}...")
            available = is_available(domain)
            if available:
                print(f"Found available domain: {domain}")
                append_domain(found_file, domain)
                found_domains.add(domain)
            else:
                print(f"{domain} is taken.")
                append_domain(taken_file, domain)
                taken_domains.add(domain)

            attempts += 1

        except Exception as e:
            print(f"Unexpected error: {e}. Continuing.")
            attempts += 1
            time.sleep(1)

    print("Completed search attempts.")

if __name__ == '__main__':
    main()
