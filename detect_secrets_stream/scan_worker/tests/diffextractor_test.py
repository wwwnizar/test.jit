from unittest import TestCase

from detect_secrets_stream.scan_worker.diffextractor import DiffExtractor
from detect_secrets_stream.scan_worker.diffextractor import DiffLineNumberOutOfRange


class DiffExtractorTest (TestCase):

    def setUp(self):
        self.test_data_path = 'detect_secrets_stream/scan_worker/test_data/diff_files'
        self.de_generic = DiffExtractor(self.test_data_path + '/generic.diff')
        self.de_renamed = DiffExtractor(self.test_data_path + '/renamed.diff')
        self.de_removed = DiffExtractor(self.test_data_path + '/removed.diff')
        self.de_created = DiffExtractor(self.test_data_path + '/created.diff')
        self.de_aslash_bslash = DiffExtractor(
            self.test_data_path + '/aslash_bslash.diff',
        )
        self.de_aslash_bslash_rename = DiffExtractor(
            self.test_data_path + '/aslash_bslash_rename.diff',
        )
        self.de_create_empty = DiffExtractor(
            self.test_data_path + '/create_empty.diff',
        )
        self.de_delete_empty = DiffExtractor(
            self.test_data_path + '/delete_empty.diff',
        )
        self.de_rename_no_changes = DiffExtractor(
            self.test_data_path + '/rename_no_changes.diff',
        )
        self.de_no_offset = DiffExtractor(
            self.test_data_path + '/no_offset.diff',
        )

    def test_extract_filename_linenumbers(self):
        # test linenumber, secret is on the same line as the line number information
        result = self.de_generic.extract_filename_linenumbers([62, 14, 1])
        self.assertIn(14, result.keys())
        self.assertIn(62, result.keys())
        self.assertIn(1, result.keys())

        self.assertEqual(result[14]['linenumber'], 40)
        self.assertEqual(result[62]['linenumber'], 167)
        self.assertEqual(result[1]['linenumber'], -1)

    def test_extract_filename_linenumber(self):
        """
        extract_filename_linenumber(diff_file_linenumber) should return the
        expected linenumber where a secret was located in the source file
        if given the line where the secret was found in the diff file
        """

        # test linenumber, secret is on the same line as the line number information
        result = self.de_generic.extract_filename_linenumber(62)
        expected = 167
        self.assertEqual(result['linenumber'], expected)

        # test linenumber in some more normal cases
        result = self.de_generic.extract_filename_linenumber(14)
        expected = 40
        self.assertEqual(result['linenumber'], expected)

        result = self.de_generic.extract_filename_linenumber(25)
        expected = 49
        self.assertEqual(result['linenumber'], expected)

        result = self.de_generic.extract_filename_linenumber(34)
        expected = 55
        self.assertEqual(result['linenumber'], expected)

        result = self.de_generic.extract_filename_linenumber(93)
        expected = 213
        self.assertEqual(result['linenumber'], expected)

        result = self.de_generic.extract_filename_linenumber(109)
        expected = 240
        self.assertEqual(result['linenumber'], expected)

        # check filename functionality
        expected_filename = 'diffscanworker.py'
        self.assertEqual(result['filename'], expected_filename)

    def test_extract_filename_linenumber_renamed_file(self):
        """
        If the file was renamed, extract_filename_linenumber should return
        the old filename if the secret was removed and the new filename if not.
        """

        # file renamed and secret removed, report old filename
        before_rename_filename = 'diffextractor.py'
        result = self.de_renamed.extract_filename_linenumber(19)
        self.assertEqual(before_rename_filename, result['filename'])
        # check linenumber
        expected_linenumber = 42
        self.assertEqual(result['linenumber'], expected_linenumber)

        # file renamed but secret not removed, report new filename
        renamed_filename = 'diffrn.py'
        result = self.de_renamed.extract_filename_linenumber(22)
        self.assertEqual(renamed_filename, result['filename'])
        # check linenumber
        expected_linenumber = 45
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_extract_filename_linenumber_deleted_file(self):
        """
        If the file was deleted, extract_filename_linenumber should return
        the name of the deleted file.
        """

        # file deleted, report old filename
        deleted_filename = 'gd_db_tools.py'
        result = self.de_removed.extract_filename_linenumber(42)
        self.assertEqual(deleted_filename, result['filename'])
        # check linenumber
        expected_linenumber = 3
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_extract_filename_linenumber_created_file(self):
        """
        If the file was created, extract_filename_linenumber should return
        the name of the new file.
        """

        # file created, report new filename
        created_filename = 'diffextractor.py'
        result = self.de_created.extract_filename_linenumber(13)
        self.assertEqual(created_filename, result['filename'])
        # check linenumber
        expected_linenumber = 7
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_filename_has_spaces_and_aslash_bslash(self):
        """
        If the filename has spaces or a/ b/ in it, extract_filename_linenumber
        should still return that filename.
        """

        expected_filename = 'a b/a'
        result = self.de_aslash_bslash.extract_filename_linenumber(7)
        self.assertEqual(expected_filename, result['filename'])
        # check linenumber
        expected_linenumber = 1
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_renamed_file_with_aslash_bslash(self):
        """
        If the filename has spaces or a/ b/ in it and the file was renamed,
        extract_filename_linenumber should still return that filename.
        """

        expected_filename_secret_removed = 'a b/a'
        result = self.de_aslash_bslash_rename.extract_filename_linenumber(10)
        self.assertEqual(expected_filename_secret_removed, result['filename'])
        # check linenumber
        expected_linenumber = 4
        self.assertEqual(result['linenumber'], expected_linenumber)

        expected_filename_secret_not_removed = 'a b/b'
        result = self.de_aslash_bslash_rename.extract_filename_linenumber(14)
        self.assertEqual(
            expected_filename_secret_not_removed,
            result['filename'],
        )
        # check linenumber
        expected_linenumber = 7
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_no_offset_in_filenumbers(self):
        """
        Some diffs, like the ones from the pipeline-tester repo, don't have
        an offset after the linenumber. i.e. The linenumber format looks like
        @@ -1 +1 @@ instead of @@ -1,1 +1,1 @@. Ensure these are handled properly.
        """

        expected_filename = 'test-secrets/test-secret-file'
        result = self.de_no_offset.extract_filename_linenumber(6)
        self.assertEqual(expected_filename, result['filename'])
        expected_linenumber = 1
        self.assertEqual(result['linenumber'], expected_linenumber)
        result = self.de_no_offset.extract_filename_linenumber(7)
        self.assertEqual(expected_filename, result['filename'])
        expected_linenumber = 1
        self.assertEqual(result['linenumber'], expected_linenumber)

    def test_metadata_lines(self):
        """
        If secret is found on a diff file metadata line, line number returned
        by extract_filename_linenumber should be -1
        """

        expected_filename = ''
        for i in range(1, 4):
            result = self.de_generic.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(1, 6):
            result = self.de_renamed.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(34, 38):
            result = self.de_removed.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(1, 5):
            result = self.de_created.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(1, 3):
            result = self.de_create_empty.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(1, 3):
            result = self.de_delete_empty.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

        for i in range(1, 4):
            result = self.de_rename_no_changes.extract_filename_linenumber(i)
            self.assertEqual(expected_filename, result['filename'])
            expected = -1
            self.assertEqual(result['linenumber'], expected)

    def test_diff_linenumber_out_of_range(self):
        """
        If extract_filename_linenumber is given a diff_file_linenumber
        that is outside the boundaries of the diff file, it should
        raise a DiffLineNumberOutOfRange exception.
        """
        with self.assertRaises(DiffLineNumberOutOfRange):
            self.de_generic.extract_filename_linenumber(-1)
        with self.assertRaises(DiffLineNumberOutOfRange):
            self.de_generic.extract_filename_linenumber(1000)
