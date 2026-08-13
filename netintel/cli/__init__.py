"""Command-line front end.

Deliberately does not re-export ``main`` from :mod:`netintel.cli.main`: binding
the name ``main`` on the package would shadow the submodule of the same name,
so ``netintel.cli.main`` would resolve to a function for some importers and to
a module for others. Import the module explicitly instead.
"""
