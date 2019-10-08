# Contribute to netprobify

## Requirements

Pull requests require the following:
- unit tests
- documentation via DocStrings, and update README.md if needed
- coding style respected

## Environment

Please see the README.md file. It contains everything needed to run the tests and build the project.

## When my PR will be reviewed and merged?

Usually, we expect reviews to be done under one month of delay.

However, the delay might increase if there is too much pending PR or big features being developped internally.

Once the code has been reviewed and validated, it will be merged into the dev branch.

## Version release

Each version will be tested under stable environment.

Once the code is proven to be stable enough, it will be merged to the stable branch.

New features will set a new major version.

Fixes, or minor changes will set a new minor version.

## Coding style

### PEP, coding style and documentation

The code is using pylama and pydocstyle to ensure PEP8 and PEP257 are respected.

The maximum length of a line in 100 characters.

Please:
- provide clear docstring containing description and attributes details (see pep257)
- comment your code to make sure the purpose of the block code is clear
- update the changelog (except for specific dynamic modules)

## Logging

Logging is important and help to debug in case of issues. Please use the logger and the right severity.

## Black formatting

Please use black before each commit to format your code: https://github.com/ambv/black

The black parameters are already set, you just need to run `black .`