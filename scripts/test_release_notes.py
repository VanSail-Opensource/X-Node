import unittest

from release_notes import extract_notes


class ReleaseNotesTest(unittest.TestCase):
    def test_extracts_only_exact_version_and_preserves_subheadings(self):
        notes = "# X-Node v2.0.18\n\nLatest.\n\n# X-Node v2.0.17\n\n## Fixes\n\nOlder.\n\n# X-Node v2.0.16\n\nPrevious.\n"
        self.assertEqual(extract_notes(notes, "v2.0.17"), "# X-Node v2.0.17\n\n## Fixes\n\nOlder.\n")

    def test_rejects_invalid_missing_duplicate_and_empty_sections(self):
        for document, version in [
            ("# X-Node v2.0.17\n\nNotes.\n", "v2.0.17-extra"),
            ("# X-Node v2.0.18\n\nNotes.\n", "v2.0.17"),
            ("# X-Node v2.0.17\n\nOne.\n# X-Node v2.0.17\n\nTwo.\n", "v2.0.17"),
            ("# X-Node v2.0.17\n\n# X-Node v2.0.16\n\nNotes.\n", "v2.0.17"),
        ]:
            with self.subTest(document=document, version=version):
                with self.assertRaises(ValueError):
                    extract_notes(document, version)


if __name__ == "__main__":
    unittest.main()
