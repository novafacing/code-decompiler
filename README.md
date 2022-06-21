# code-decompiler README

![demovideo](rsrc/output.gif)

This is SUPER WIP!!! Don't use it yet!

All that is working so far is:
* Create memfs to store decomp results
* Compile protobuf to talk to python decomp manager server
* Right click action to "Decompile" a file

# Dependencies

You will need a couple global pip dependencies:

`python3 -m pip install grpcio-tools grpcio protobuf`

# Install

Just in case someone wants to hack on this, some bad instructions:

Clone the repo, make sure you have installed the above dependencies, as well as node.js
and poetry.

Next, run `npm run compile` to compile the protocol files and the extension.

Finally, you should be able to F5 in VSCode and run it in another VSCode window.
