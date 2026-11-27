# Cyber Digital Twin

## Quick start (Windows / PowerShell)

Run these from the project folder:

    .\run setup       # once: installs the requirements
    .\run validate    # check data\network.json
    .\run twin        # build the digital twin
    .\run test        # run all tests

`run.bat` always uses the project's `.venv`, so no activation is needed.

## Project layout

    data/network.json                 the network description
    data/schema/network.schema.json   the rules (JSON Schema)
    data/schema/src/validate_config.py   stage 1 (schema) + stage 2 (relationships)
    src/build_twin.py                 config -> graph (networkx)
    tests/, data/schema/tests/        unit tests
