#!/usr/bin/env python

import re
import os.path
import sys
import argparse
import subprocess
import pickle
from enum import Enum

# FIXME: handle import errors
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

# FIXME: handle import errors
import docx
from xml.etree import ElementTree

XCCDF12_NS = "http://checklists.nist.gov/xccdf/1.2"
OVAL_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"
IGNITION_SYSTEM = "urn:xccdf:fix:script:ignition"
KUBERNETES_SYSTEM = "urn:xccdf:fix:script:kubernetes"
OCIL_SYSTEM = "http://scap.nist.gov/schema/ocil/2"

XCCDF_RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"
XCCDF_PROFILE_PREFIX = "xccdf_org.ssgproject.content_profile_"

SECTION_RE = r'[0-9]+\.[0-9]+(\.[0-9]+)?'
section_re = re.compile(SECTION_RE)

OPENXML_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
AUDIT_BG_COLOR = "ddd9c4"

AUDIT_NEEDS_VERIFICATION_BLOB = "# needs verification"

DOCUMENT_ID = '1zf7viEiewDvbWoTLYbSub66sr_niIqsyRwPyy623Akk'

def removeprefix(fullstr, prefix):
    if fullstr.startswith(prefix):
        return fullstr[len(prefix):]
    else:
        return fullstr

class RuleProperties:
    def __init__(self, profile_id, repo_path):
        self.profile_id = profile_id
        self.repo_path = repo_path
        self.rule_id = None
        self.name = None
        self.fix = False
        self.ignition_fix = False
        self.kubernetes_fix = False
        self.ocil_check = False
        self.oval = False
        self.e2etest = False
        self.cis_id = ""

    def __repr__(self):
        return "%s: %s: %s" % (self.profile_id, self.cis_id, self.rule_id)

    def __str__(self):
        return "%s: %s: %s" % (removeprefix(self.profile_id, XCCDF_PROFILE_PREFIX), self.cis_id, self.name)

    def from_element(self, el):
        self.rule_id = el.get("id")
        self.name = removeprefix(self.rule_id, XCCDF_RULE_PREFIX)
        oval = el.find("./{%s}check[@system=\"%s\"]" %
                         (XCCDF12_NS, OVAL_NS))
        ignition_fix = el.find("./{%s}fix[@system=\"%s\"]" %
                                 (XCCDF12_NS, IGNITION_SYSTEM))
        kubernetes_fix = el.find("./{%s}fix[@system=\"%s\"]" %
                                   (XCCDF12_NS, KUBERNETES_SYSTEM))
        ocil_check = el.find("./{%s}check[@system=\"%s\"]" %
                               (XCCDF12_NS, OCIL_SYSTEM))
        cis_id = el.find("./{%s}reference" %
                           (XCCDF12_NS))

        self.cis_id = cis_id.text
        self.ocil_check = False if ocil_check is None else True
        self.oval = False if oval is None else True
        self.ignition_fix = False if ignition_fix is None else True
        self.kubernetes_fix = False if kubernetes_fix is None else True
        self.fix = self.ignition_fix or self.kubernetes_fix
        return self

    def _get_rule_path(self):
        cmd = ["find", self.repo_path, "-name", self.name, "-type", "d"]
        process = subprocess.run(cmd, stdout=subprocess.PIPE, universal_newlines=True)
        if process.returncode != 0:
            print("WARNING: Rule path not found for rule: %s" % self.name)
            return None
        return process.stdout.strip("\n")

    def verify_tests(self):
        if self.repo_path is None:
            return
        path = self._get_rule_path()
        if path is None:
            return
        e2etestpath = os.path.join(path, "tests", "ocp4", "e2e.yml")
        if os.path.isfile(e2etestpath):
            self.e2etest = True


class BenchmarkStats:
    def __init__(self, cis_bench_stats, check_tests):
        self.missing_ocil = list()
        self.missing_oval = list()
        self.missing_e2e_test = list()
        self.rules = list()
        self.rules_with_oval = list()
        self.rules_with_remediation = list()
        self.rules_missing_remediation = list()

        self.by_id = dict()
        for s in cis_bench_stats:
            self.by_id[s.section] = list()

        self.n_rule_not_implemented = 0
        self.n_rule_implemented = 0

        self.check_tests = check_tests

    def add(self, rule):
        if rule.cis_id not in self.by_id.keys():
            raise ValueError("Rule %s does not belong to the CIS profiles" % rule.cis_id)

        self.rules.append(rule)
        self.by_id[rule.cis_id].append(rule)
        if rule.ocil_check == False:
            self.missing_ocil.append(rule)
        if rule.oval == False:
            self.missing_oval.append(rule)
        else:
            if rule.fix:
                self.rules_with_remediation.append(rule)
            else:
                self.rules_missing_remediation.append(rule)
            self.rules_with_oval.append(rule)


        if self.check_tests and rule.oval and not rule.e2etest:
            self.missing_e2e_test.append(rule)

    @property
    def not_implemented_rules(self):
        return [ r for r in self.by_id.values() if len(r) == 0 ]

    @property
    def implemented_rules(self):
        return [ r for r in self.by_id.values() if len(r) > 0 ]


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
        self.has_audit = False
        self.audit_verified = True

    def __repr__(self):
        return "%s: %s" % (self.section, self.title)


class CisBenchKind(Enum):
    DOCX = 1
    GDOC = 2


class NoCredsError(Exception):
    def __str__(self):
        return "Please make sure to install a gdoc app and fetch credentials.json"


class GdocCisDoc:
    CACHE_FILENAME = 'doc.pickle'
    TOKEN_PICKLE = 'token.pickle'
    # If modifying these scopes, delete the file token.pickle.
    SCOPES = ['https://www.googleapis.com/auth/documents.readonly']

    def __init__(self, doc_id, cache=False):
        document = None
        if os.path.exists(GdocCisDoc.CACHE_FILENAME) and cache == True:
            with open(GdocCisDoc.CACHE_FILENAME, 'rb') as doc:
                document = pickle.load(doc)

        if not document:
            document = self._get_document(doc_id)
            with open(GdocCisDoc.CACHE_FILENAME, 'wb') as doc:
                pickle.dump(document, doc)
        else:
            print("INFO: Using cached document")

        self._doc = document

    def _get_document(self, doc_id):
        creds = None
        # The file token.pickle stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists(GdocCisDoc.TOKEN_PICKLE):
            with open(GdocCisDoc.TOKEN_PICKLE, 'rb') as token:
                creds = pickle.load(token)

        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(
                            'credentials.json', GdocCisDoc.SCOPES)
                except FileNotFoundError:
                    raise NoCredsError()

                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(GdocCisDoc.TOKEN_PICKLE, 'wb') as token:
                pickle.dump(creds, token)

        service = build('docs', 'v1', credentials=creds)
        # Retrieve the documents contents from the Docs service.
        return service.documents().get(documentId=doc_id).execute()

    def read_controls(self):
        ctrl = None
        sections = []
        content = self._doc.get('body').get('content')
        for citem in content:
            para = citem.get('paragraph')
            if para == None:
                continue
            if self._is_ctrl_header(para):
                text = self._get_para_text(para)
                ctrl = CisCtrl(text)
                sections.append(ctrl)
            if self._is_audit(para):
                if ctrl == None:
                    raise ValueError("Audit outside section?")
                ctrl.has_audit = True

                text = self._get_para_text(para)
                if AUDIT_NEEDS_VERIFICATION_BLOB in text:
                    ctrl.audit_verified = False

        return sections

    def _get_para_text(self, para):
        return ''.join([ el.get('textRun').get('content') for el in para.get('elements')])

    def _is_ctrl_header(self, para):
        style = para.get('paragraphStyle')
        if style == None or style.get('namedStyleType') != 'HEADING_3':
            return False

        text = self._get_para_text(para)
        m = section_re.match(text)
        if m is None:
            return False

        return True

    def _is_audit(self, para):
        style = para.get('paragraphStyle')
        if style == None or style.get('namedStyleType') != 'NORMAL_TEXT':
            return False

        try:
            shadingRgb = style['shading']['backgroundColor']['color']['rgbColor']
        except KeyError:
            return False
        if shadingRgb['red'] != 0.8666667 or shadingRgb['green'] != 0.8509804 or shadingRgb['blue'] != 0.76862746:
            return False

        return True


class DocxCisDoc:
    def __init__(self, filename):
        self._doc = docx.Document(filename)

    def read_controls(self):
        ctrl = None
        sections = []
        for p in self._doc.paragraphs:
            if self._is_ctrl_header(p):
                ctrl = CisCtrl(p.text)
                sections.append(ctrl)

            if self._is_audit(p):
                if ctrl == None:
                    raise ValueError("Audit outside section?")
                ctrl.has_audit = True

                if AUDIT_NEEDS_VERIFICATION_BLOB in p.text:
                    ctrl.audit_verified = False
        return sections

    def _is_audit(self, paragraph):
        if paragraph.style.name != "normal":
            return False

        tree = ElementTree.fromstring(paragraph.paragraph_format.element.xml)
        if tree == None:
            return False

        # This is hacky, but python-docx does not seem to provide the background
        # color as an attribute, so let's read it from the XML directly
        has_audit_bg = tree.find(".//{%s}shd[@{%s}fill=\"%s\"]" % (OPENXML_NS, OPENXML_NS, AUDIT_BG_COLOR))
        if has_audit_bg == None:
            return False

        return True

    def _is_ctrl_header(self, paragraph):
        if paragraph.style.name != "Heading 3":
            return False

        m = section_re.match(paragraph.text)
        if m is None:
            return False

        return True


class CisDoc:
    def __init__(self, doc_type, source, cache=False):
        if doc_type == CisBenchKind.DOCX:
            self._doc = DocxCisDoc(source)
        elif doc_type == CisBenchKind.GDOC:
            self._doc = GdocCisDoc(source, cache)
        else:
            raise ValueError("Unknown document type ", doc_type)

    def read_controls(self):
        return self._doc.read_controls()


def process_rules(rule_stats, rules,  profile, repo_path):
    for rule in rules:
        if rule is None:
            continue

        rprop = RuleProperties(profile, repo_path).from_element(rule)
        if rprop is None:
            continue

        rprop.verify_tests()

        try:
            rule_stats.add(rprop)
        except ValueError as e:
            print(e)

    return rule_stats


def print_statline(title, sub_i, total_i):
    sub = len(sub_i)
    total = len(total_i)
    if total == 0:
        percent = 0
    else:
        percent = 100.0 * (sub/total)
    print("\t%d/%d (%.2f%%) of %s" % (sub, total, percent, title))


def main():
    parser = argparse.ArgumentParser(prog="cisstats.py")

    parser.add_argument("--cis-path", help="The path to the CIS benchmark")
    parser.add_argument("--gdoc",
                        action='store_true',
                        help="Fetch the CIS benchmark from a google doc")
    parser.add_argument("--cached-gdoc",
                        default=False,
                        action='store_true',
                        help="Use a cached version of the gdoc if available")

    parser.add_argument("--ds-path", help="The path to the DataStream file")
    parser.add_argument("--repo-path", default=None, help="The path to the CaC repo to read DS from")

    parser.add_argument('--no-rebuild',
                        dest='rebuild',
                        action='store_false',
                        help='Do not rebuild the content in --repo-path (default: rebuild)')
    parser.set_defaults(rebuild=True)
    parser.add_argument("--profiles",
                        default="xccdf_org.ssgproject.content_profile_cis,xccdf_org.ssgproject.content_profile_cis-node",
                        help="The XCCDF IDs of the profiles to analyze")

    args = parser.parse_args()

    if args.gdoc == True:
        doc = CisDoc(CisBenchKind.GDOC, DOCUMENT_ID, args.cached_gdoc)
    elif args.cis_path:
        doc = CisDoc(CisBenchKind.DOCX, args.cis_path)
    else:
        print("Please provide path to a docx export with --cis-patch or load from a google document using --gdoc")
        sys.exit(1)

    cis_control_sections = doc.read_controls()
    check_tests = args.repo_path is not None
    stats = BenchmarkStats(cis_control_sections, check_tests)
    if args.ds_path:
        ds_path = args.ds_path
    elif args.repo_path:
        ds_path = os.path.join(args.repo_path, "build/ssg-ocp4-ds.xml")
        if args.rebuild == True:
            buildscript_path = os.path.join(args.repo_path, "build_product")
            buildp = subprocess.run(capture_output=True, args=[buildscript_path, "--datastream-only", "ocp4"], cwd=args.repo_path)
            if buildp.returncode != 0:
                print("Could not rebuild the content")
                sys.exit(1)
    else:
        print("Please specify either --repo-path or --ds-path")
        sys.exit(1)

    bench = XCCDFBenchmark(ds_path)
    for profile in [p for p in args.profiles.split(',')]:
        if not profile.startswith(XCCDF_PROFILE_PREFIX):
            profile = XCCDF_PROFILE_PREFIX + profile

        rules = bench.get_rules(profile)
        stats = process_rules(stats, rules, profile, args.repo_path)

    print("* Rules not covered by neither cis.profile nor cis-node.profile")
    for s in cis_control_sections:
        if len(stats.by_id[s.section]) == 0:
            print("\t%s: %s" % (s.section, s.title))
    print()

    print("* Rules with missing OCIL")
    for no_ocil in stats.missing_ocil:
        print("\t" + str(no_ocil))
    print()

    print("* Rules with missing OVAL")
    for no_oval in stats.missing_oval:
        print("\t" + str(no_oval))
    print()

    print("* Rules with remediation")
    for rem_rule in stats.rules_with_remediation:
        print("\t" + str(rem_rule))
    print()

    print("* Rules missing remediation")
    for no_rem_rule in stats.rules_missing_remediation:
        print("\t" + str(no_rem_rule))
    print()

    if stats.check_tests:
        print("* Rules with missing e2e tests")
        for no_e2e in stats.missing_e2e_test:
            print("\t" + str(no_e2e))
        print()

    print("* Statistics")
    print_statline("controls implemented in either profile", stats.implemented_rules, stats.by_id)
    print_statline("controls missing in both profiles", stats.not_implemented_rules, stats.by_id)
    print_statline("controls missing OCIL", stats.missing_ocil, stats.implemented_rules)
    print_statline("controls missing OVAL", stats.missing_oval, stats.implemented_rules)
    print_statline("controls with remediation", stats.rules_with_remediation, stats.rules_with_oval)
    print_statline("controls missing remediation", stats.rules_missing_remediation, stats.rules_with_oval)
    if stats.check_tests:
        print_statline("rules missing e2e tests", stats.missing_e2e_test, stats.rules_with_oval)

if __name__ == "__main__":
    main()
