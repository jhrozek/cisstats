#!/usr/bin/env python

import docx
import re
import argparse

from xml.etree import ElementTree

XCCDF12_NS = "http://checklists.nist.gov/xccdf/1.2"
OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
IGNITION_SYSTEM = "urn:xccdf:fix:script:ignition"
KUBERNETES_SYSTEM = "urn:xccdf:fix:script:kubernetes"

SECTION_RE = '[0-9]+\.[0-9]+(\.[0-9]+)?'
section_re = re.compile(SECTION_RE)


class RuleStats:
    def __init__(self, rule_id):
        self.rule_id = rule_id

        self.ignition_fix = False
        self.kubernetes_fix = False
        self.cis_id = ""

    def __str__(self):
        return "%s: %s" % (self.rule_id, self.cis_id)


class XCCDFBenchmark:
    def __init__(self, filepath):
        self.tree = None
        with open(filepath, 'r') as xccdf_file:
            file_string = xccdf_file.read()
            tree = ElementTree.fromstring(file_string)
            self.tree = tree

        self.indexed_rules = {}
        for rule in self.tree.findall(".//{%s}Rule" % (XCCDF12_NS)):
            rule_id = rule.get("id")
            if rule_id is None:
                raise ValueError("Can't index a rule with no id attribute!")

            if rule_id in self.indexed_rules:
                raise ValueError("Multiple rules exist with same id attribute: %s!" % rule_id)

            self.indexed_rules[rule_id] = rule

    def get_rules(self, profile_name):
        xccdf_profile = self.tree.find(".//{%s}Profile[@id=\"%s\"]" %
                                        (XCCDF12_NS, profile_name))
        if xccdf_profile is None:
            raise ValueError("No such profile: %s" % profile_name)

        rules = []
        selects = xccdf_profile.findall("./{%s}select[@selected=\"true\"]" %
                                        XCCDF12_NS)
        for select in selects:
            rule_id = select.get('idref')
            xccdf_rule = self.indexed_rules.get(rule_id)
            if xccdf_rule is None:
                # it could also be a Group
                continue
            rules.append(xccdf_rule)
        return rules


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


def process_rules(rule_stats, rules):
        for rule in rules:
            if rule is None:
                continue
            rule_id = rule.get("id")
            oval = rule.find("./{%s}check[@system=\"%s\"]" %
                                (XCCDF12_NS, OVAL_NS))
            ignition_fix = rule.find("./{%s}fix[@system=\"%s\"]" %
                                    (XCCDF12_NS, IGNITION_SYSTEM))
            kubernetes_fix = rule.find("./{%s}fix[@system=\"%s\"]" %
                                        (XCCDF12_NS, KUBERNETES_SYSTEM))
            cis_id = rule.find("./{%s}reference" %
                               (XCCDF12_NS))

            rstat = RuleStats(rule_id)
            rstat.cis_id = cis_id.text
            rstat.ignition_fix = False if ignition_fix is None else True
            rstat.kubernetes_fix = False if kubernetes_fix is None else True
            rule_stats[rstat.cis_id] = rstat
        return rule_stats


def main():
    parser = argparse.ArgumentParser(prog="cisstats.py")

    parser.add_argument("--ds-path", help="The path to the dataStream")
    parser.add_argument("--cis-path", help="The path to the CIS benchmark")
    # TODO: profile list
    parser.add_argument("--profiles",
                        default="cis",
                        help="The name of the profile to analyze")

    args = parser.parse_args()

    if args.cis_path:
        doc = CisDoc(args.cis_path)
        cis_control_sections = doc.read_sections()

    stats = {}
    if args.ds_path:
        bench = XCCDFBenchmark(args.ds_path)
        for profile in [p for p in args.profiles.split(',')]:
            rules = bench.get_rules(profile)
            stats = process_rules(stats, rules)

    for s in cis_control_sections:
        if s.section not in stats.keys():
            print("Rule %s not covered by cis content" % s.section)
    print("%d/%d covered by CIS profile" % (len(stats.keys()), len(cis_control_sections)))

if __name__ == "__main__":
    main()
