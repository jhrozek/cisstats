## About

A script to process the OCP CIS benchmark draft, either as a google doc,
with optional caching or as a DOCX export. Cross-checks the document
with the compliance-as-code `cis.profile` and `cis-node.profile`.

The output can be found [here](https://jhrozek.fedorapeople.org/cis_stats.txt),
generated once per hour.

## Setup

Install the dependencies

Fedora:

```
$ sudo dnf install python3-google-api-client.noarch python3-google-api-client.noarch python3-google-auth.noarch python3-google-auth-oauthlib.noarch python3-docx.noarch
```

Get the `credentials.json` file by doing the first step of the following doc:

[https://developers.google.com/docs/api/quickstart/python?authuser=1](
https://developers.google.com/docs/api/quickstart/python?authuser=1)

## Runtime

A typical use looks like:
```
$ python3 cisstats.py --gdoc --repo-path=/path/to/compliance-as-code-content
```
The first time the script runs, it would open a browser and ask you to
give consent to access the CIS document. 

The google doc can be slow to load. To use a locally cached version (useful if
you iterate on the content), add `--cached-gdoc`. The content is also rebuild
every time, to suppress that, if you're just iterating on the doc, use
`--no-rebuild`.

To point to a `.docx` export for offline use instead of the google doc source,
use `--cis-path`.
