====
pigg
====

Python implementation of garbled gates and 2PC boolean circuit protocols.

Requirements and Installation
-----------------------------
This library works with Python 3.8 or higher. The required packages can be installed as follows::

    python -m pip install -r requirements.txt 

PIGG does not require `libsodium <https://github.com/jedisct1/libsodium>`_ to be installed in the environment and can rely on native Python implementations of cryptographic primitives in conjunction with an instance of the `PyNaCl <https://github.com/pyca/pynacl/>`_ package (PyNaCl comes with its own instance of a compiled libsodium library). However, it will use libsodium primitives if it can find the library installed in the environment.

Test Suite
----------
The test suite checks a variety of library functionalities. It can be invoked as follows from inside the ``test/`` directory. Run the test suite on the library itself (with a programmatically simulated server object where applicable) in the following way::

    python test.py library

To to test the HTTP API between a client and server, start a server in the following way::

    python test.py library server

Running ``python test.py library`` as usual after the above in another terminal session will cause the test suite client to compute with the help of the server.

If PIGG or HUGG merged modules have been created using the module merging tool (described below), they can also be tested independently of the library. The following will test the PIGG merged module (with a simulated server object)::

    python test.py pigg

As before, running ``python test.py pigg server`` and ``python test.py pigg`` simultaneously will run the PIGG module tests that rely on a client-server interactions.

To test the HUGG merged modules, start a HUGG server in the following way::

    python test.py huggs

Next, test the HUGG client's interactions with the server in the following way::

    python test.py hugg

Tools
-----
The library is accompanied by a number of tools for synthesizing circuits, for embedding those circuits within Python (e.g., for easier packaging and faster loading), and for merging the library modules into a single, standalone Python module (e.g., for portability and easier distribution within other projects).

Tool scripts usually assume that they are being invoked from inside the ``tool/`` directory.

Synthesis
^^^^^^^^^
The circuit synthesis script can be run in the following way::

    python synth.py sha-256 aes-128

The synthesized circuits should normally be placed inside the ``circuit/bristol`` directory. Please place function definitions that correspond to new circuits into the ``tool/synth`` directory.

Embedding
^^^^^^^^^
The embedding script creates Python source files that contain circuit definitions. It also creates C++ header files that can be included within a compiled CIGG library file or executable. The script can be run in the following way::

    python embed.py

The embedded circuit definitions are placed in the ``circuit/embedded/`` directory.

Module Merging
^^^^^^^^^^^^^^
This script combines all the PIGG library source files into single Python source files that have some (e.g., client-only or server-only) or all of the library features and can be imported in other projects that rely on PIGG. It is possible to build a single source file that has all library features in the following way::

    python module.py pigg

It is also possible to build source files specifically tailored for allowing a client-server pair to jointly compute hash functions in the following way::

    python module.py hugg huggs

The tool accepts one or more arguments (e.g., ``python module.py huggs``). Once they are generated, the modules can be found in the ``module/`` directory.
