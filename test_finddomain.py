import unittest
from finddomain_ifexists import (
    has_dns_record, read_domains, append_domain, get_found_domains, get_taken_domains,
    add_found_domain, add_taken_domain, calculateFirstLetter
)

class TestFindDomainMethods(unittest.TestCase):
    def test_has_dns_record_false(self):
        # t836.com should not resolve
        self.assertFalse(has_dns_record("t836.com"))

    def test_append_and_read_domains(self):
        test_file = "test_domains.txt"
        append_domain(test_file, "abc.com")
        domains = read_domains(test_file)
        self.assertIn("abc.com", domains)
        os.remove(test_file)

    def test_get_found_domains(self):
        # Should return a set
        self.assertIsInstance(get_found_domains(), set)

    def test_get_taken_domains(self):
        # Should return a set
        self.assertIsInstance(get_taken_domains(), set)

    def test_add_found_domain(self):
        test_set = set()
        add_found_domain("xyz.com", test_set)
        self.assertIn("xyz.com", test_set)

    def test_add_taken_domain(self):
        test_set = set()
        add_taken_domain("taken.com", test_set)
        self.assertIn("taken.com", test_set)

    def test_calculateFirstLetter(self):
        found = {"abcd.com", "a123.com"}
        taken = {"a999.com"}
        count = calculateFirstLetter('a', found, taken)
        self.assertEqual(count, 3)

if __name__ == "__main__":
    unittest.main()
