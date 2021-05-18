import logging
import re


class DiffLineNumberOutOfRange(Exception):
    pass


class DiffExtractor(object):

    def __init__(self, diff_file_path):
        self.diff_file_path = diff_file_path
        self.filenames_regex = re.compile(r'diff --git a/(.*) b/(\1)')
        self.linenumber_regex = re.compile(
            r'@@ -([0-9]+)(?:,[0-9]+|) \+([0-9]+)(?:,[0-9]+|) @@',
        )
        self.logger = logging.getLogger(__name__)

    def extract_filename_linenumber(self, diff_file_linenumber: int):
        """
        For incoming line number, return original file info. See generator function
        _extract_filename_linenumbers's docstring for more details.

        Accepts:
            diff_file_linenumber: the line number in the diff file where the secret was found

        Returns: dict
            - key: the original secret file name where the secret was found
            - value: the line number where the secret was found in the original file

            If input line number is in diff file metadata lines, result dict is {"": -1}

        Throws: DiffLineNumberOutOfRange exception if line number provided is out of range
        of the diff file

        Example:
            - input is 1
            - returns is {"filename": <original_file_line_number>}
        """

        return self.extract_filename_linenumbers([diff_file_linenumber])[diff_file_linenumber]

    def extract_filename_linenumbers(self, diff_file_linenumber_list: list):
        """
        For each diff_file_linenumber in diff_file_linenumber_list, return original file info

        Accepts:
            diff_file_linenumbers: the list of line numbers in the diff file where secrets were found

        Returns: dict of format {diff_file_linenumber:
                                    {"filename": <original_filename>,
                                     "linenumber": <original_file_linenumber>}
                                 diff_file_linenumber:
                                    ...
                                }

            If input line number refers to diff file metadata lines, inner dict is {filename: "", linenumber: -1}
        """
        return {
            linenumber: result
            for linenumber, result in self._extract_filename_linenumbers(diff_file_linenumber_list)
        }

    def _extract_filename_linenumbers(self, diff_file_linenumber_list: list):
        """
        Generator function. For each line number in the input list, looks for the file name where the secret
        originally exits, and its original line number. The input line number count begins at 1.

        Accepts:
            diff_file_linenumbers: the list of line numbers in the diff file where secrets were found

        Yields: tuple, (diff_file_linenumber, dict_of_original_file_info)
            - diff_file_linenumber: the line number in incoming list
            - dict_of_original_file_info: dict of format {"filename": <original_filename>,
                                                          "linenumber": <original_file_linenumber>}

            If input line number is in diff file metadata lines, dict_of_original_file_info
            is {filename: "", linenumber: -1}

        Throws: DiffLineNumberOutOfRange exception if line number provided is out of range
        of the diff file
        """
        if not diff_file_linenumber_list:
            return None

        diff_file_linenumber_list.sort()
        with open(self.diff_file_path, 'r') as diff_file:
            diff_file_lines = diff_file.readlines()
            if diff_file_linenumber_list[-1] > len(diff_file_lines) or diff_file_linenumber_list[0] < 1:
                raise DiffLineNumberOutOfRange(
                    "The secret's line number is out of range of the diff file.",
                )

            new_start_line, old_start_line = 0, 0
            new_file_lines, old_file_lines = 0, 0
            new_filename, old_filename = '', ''
            in_metadata = False
            for current_linenumber, line in enumerate(diff_file_lines, start=1):
                if line.startswith('diff --git'):
                    in_metadata = True
                    filename_matches = re.findall(self.filenames_regex, line)
                    # only matches when file name did not change
                    # if file name changes, it would be matched by `rename from`
                    #  and `rename to` logic below
                    if filename_matches:
                        new_filename = old_filename = filename_matches[0][0]
                elif line.startswith('rename from'):
                    old_filename = line[12:-1]
                elif line.startswith('rename to'):
                    new_filename = line[10:-1]
                elif line.startswith('@@ '):
                    linenumber_matches = re.findall(
                        self.linenumber_regex, line,
                    )
                    if linenumber_matches:
                        in_metadata = False
                        new_start_line = int(linenumber_matches[0][1])
                        old_start_line = int(linenumber_matches[0][0])
                        # reset + and - counts when we encounter new line information
                        new_file_lines = 0
                        old_file_lines = 0
                elif line.startswith('+'):
                    new_file_lines += 1
                elif line.startswith('-'):
                    old_file_lines += 1
                else:
                    new_file_lines += 1
                    old_file_lines += 1

                if current_linenumber in diff_file_linenumber_list:
                    secret_filename, secert_linenumber = '', -1
                    if in_metadata:
                        # use default value
                        pass
                    elif line.startswith('-'):  # line removed
                        secret_filename = old_filename
                        secert_linenumber = old_start_line - 1 + old_file_lines
                    else:
                        secret_filename = new_filename
                        secert_linenumber = new_start_line - 1 + new_file_lines

                    self.logger.info(
                        f'''The secret {current_linenumber} was found
                        in {secret_filename} on linenumber {secert_linenumber}.''',
                    )
                    yield current_linenumber, {'filename': secret_filename, 'linenumber': secert_linenumber}
