#!/usr/bin/env python

import docx
import re

SECTION_RE = '[0-9]+\.[0-9]+(\.[0-9]+)?'
section_re = re.compile(SECTION_RE)


class CisCtrl:
    def __init__(self, full_title):
        rmatch = section_re.match(full_title)
        if rmatch is None:
            raise ValueError("full title %s does not match re" % full_title)

        self.section = rmatch.group()
        self.title = full_title.lstrip(self.section).strip()


class CisDoc:
    def __init__(self, filename):
        self._doc = docx.Document(filename)

    def read_sections(self):
        section_iter = filter(self._section_filter, self._doc.paragraphs)
        sections = []
        for s in section_iter:
            sections.append(CisCtrl(s.text))
        return sections

    def _section_filter(self, paragraph):
        if paragraph.style.name != "Heading 3":
            return False

        m = section_re.match(paragraph.text)
        if m is None:
            return False

        return True


def main():
    doc = CisDoc("cis.docx")
    cis_control_sections = doc.read_sections()
    for s in cis_control_sections:
        print(s.section, s.title)

if __name__ == "__main__":
    main()
