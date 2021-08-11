# CTFOJ
[![Build](https://github.com/jdabtieu/CTFOJ/workflows/build/badge.svg)](https://github.com/jdabtieu/CTFOJ/actions)
[![CodeQL Analysis](https://github.com/jdabtieu/CTFOJ/workflows/CodeQL/badge.svg)](https://github.com/jdabtieu/CTFOJ/actions)
[![Codecov Report](https://img.shields.io/codecov/c/github/jdabtieu/CTFOJ)](https://codecov.io/github/jdabtieu/CTFOJ/)
[![GitHub Release](https://img.shields.io/github/v/release/jdabtieu/CTFOJ)](https://github.com/jdabtieu/CTFOJ/releases)
[![AGPL-3.0 License](https://img.shields.io/github/license/jdabtieu/CTFOJ)](https://github.com/jdabtieu/CTFOJ/blob/master/LICENSE)

CTFOJ is a open-source online judge to host capture-the-flag problems and contests. It is primarily designed for capture-the-flag clubs who would like to host unlimited contests and practice problems.

## Features
- Create practice problems
    - Editorials can be created any time showing solutions
    - Export problems for archival
- Create contests
    - Contest problems support dynamic scoring
    - Contests have a live scoreboard that can be configured to be viewable by admins only or all competitors
    - Hints can be added to any problem
    - Mass notify users through email
- Create announcements
    - Announce anything you want, to all users of the site
- Custom homepage
    - Add your own customized content to a homepage displayed to all anonymous users
- Full Markdown support
- User management
    - Remotely reset passwords
    - Ban users
    - Disqualify users from contest
- 2FA support
- SMTP support
- API access
- Automatic contest starting and ending
- \+ many more


## Installation and Quickstart
See [INSTALL.md](docs/INSTALL.md).

## Support
If you are encountering any issues, please check the repository Wiki first of the issues tab.<br>
If you would like to open an issue about a feature request or bug report, please do so on the Issues tab.<br>
Otherwise, email [jdabtieu](mailto:jonathan.wu3@outlook.com) for other support.

## Usage
If you have logged in with an administrator account, you will be able to manage the site through
the "Admin Console" interface. This includes the ability to create practice problems, contests, and announcements.
Additionally, you will be able to manage users and view submissions.

## Contributing
Contributors are welcome. If you want to help, feel free to submit a pull request or open an issue. Additionally,
please make sure to test your changes manually and using our [test suite](https://github.com/jdabtieu/CTFOJ/tree/master/src/tests).

Notice a security vulnerability? Refer to [SECURITY.md](docs/SECURITY.md) to determine what to do.

#### Code Style
We encourage you to follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for
Python code, with a modification of 90 characters line length. However, longer lines may be used if
breaking the line would reduce readability.

For non-Python code, please use 4 space tabs, limit your lines to under 100 characters, use
descriptive variable names, and follow general good practices (unless it would reduce readability or performance).
