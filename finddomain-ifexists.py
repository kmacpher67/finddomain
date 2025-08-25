import random
import time
import whois  # pip install python-whois
import os
import socket


FOUND_FILE = "found4charcomain.txt"
TAKEN_FILE = "taken4domain.txt"

def get_found_domains():
    """Return the set of found domains from the file."""
    return read_domains(FOUND_FILE)

def get_taken_domains():
    """Return the set of taken domains from the file."""
    return read_domains(TAKEN_FILE)

def add_found_domain(domain, found_domains):
    """Add a domain to the found file and set."""
    append_domain(FOUND_FILE, domain)
    found_domains.add(domain)

def add_taken_domain(domain, taken_domains):
    """Add a domain to the taken file and set."""
    append_domain(TAKEN_FILE, domain)
    taken_domains.add(domain)

def has_dns_record(domain, timeout=1):
    """
    Check if a domain name resolves via DNS (i.e., has an IP address).
    This is a fast, cost-free way to filter out registered domains before performing a WHOIS lookup.

    Reasoning:
    - DNS lookups are lightweight and can be performed rapidly for many domains.
    - If a domain resolves, it is almost certainly registered.
    - WHOIS queries are only needed for domains that do not resolve, to check if they are truly available.
    - DNS lookups do not guarantee availability (some registered domains may not resolve), but they are a good first filter.

    Args:
        domain (str): The domain name to check.
        timeout (int): Timeout in seconds for the DNS lookup (default: 2).

    Returns:
        bool: True if the domain resolves (registered), False otherwise.
    """
    try:
        # Set a timeout for the DNS query to avoid hanging
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        # Domain does not resolve
        return False
    except Exception as e:
        # Other errors (e.g., network issues)
        return False

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

def generate_domain(found_domains, taken_domains, max_retries=9999):
    """
    Generate a random 4-character .com domain that:
    - Has not already been checked (not in found_domains or taken_domains)
    - Does not resolve via DNS (using has_dns_record)

    Args:
        found_domains (set): Domains already found available.
        taken_domains (set): Domains already found taken.
        max_retries (int): Maximum attempts to find a suitable domain.

    Returns:
        str: A domain name meeting the criteria.
    """
    allowed_first = 'abcdefghijklmnopqrstuvwxyz0123456789'
    allowed_mid = allowed_first + '-'
    allowed_last = allowed_first

    for _ in range(max_retries):
        domain = (
            random.choice(allowed_first) +
            random.choice(allowed_mid) +
            random.choice(allowed_mid) +
            random.choice(allowed_last)
        ) + '.com'

        if domain in found_domains or domain in taken_domains:
            # Already checked, skip
            print(f"Generated domain {domain} insider generate domain.")
            continue
        if has_dns_record(domain):
            # Domain resolves, so it's likely taken; save and skip
            print(f"{domain} resolves via DNS, is taken, regen again.")
            add_taken_domain(domain, taken_domains)
            continue
        return domain
    raise RuntimeError("Could not generate a suitable domain after many attempts.")

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

    # Load previously checked domains from files.
    found_domains = get_found_domains()
    taken_domains = get_taken_domains()

    attempts = 0
    max_attempts = 99999  # Adjust as needed

    while attempts < max_attempts:
        try:
            domain = generate_domain(found_domains, taken_domains)

            print(f"Checking {domain}...")
            available = is_available(domain)
            if available:
                print(f"Found available domain: {domain}")
                add_found_domain(domain, found_domains)
            else:
                print(f"{domain} is taken.")
                add_taken_domain(domain, taken_domains)

            attempts += 1
            time.sleep(1)  # Pause to reduce load / avoid rate limits

        except Exception as e:
            print(f"Unexpected error: {e}. Continuing.")
            attempts += 1
            time.sleep(1)

    print("Completed search attempts.")

if __name__ == '__main__':
    main()
