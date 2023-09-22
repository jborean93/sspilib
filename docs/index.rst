Python SSPI: SSPI Bindings for Python
=====================================

The Security Support Provider Interface (SSPI) is a set of APIs on WIndows that
exposes ways to perform authentication or other security related scenarios. The
goal of this library is to expose those raw C APIs inside Python through a
managed layer while also offering an easier high level API.

The high level API is exposed through the ``sspi`` namespace whereas the low
level API that exposes the SSPI functions are located in ``sspi.raw``.

.. toctree::
   :hidden:
   :maxdepth: 3

   sspi.md
   sspi.raw.md

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
