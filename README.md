# Python TFTP

This is a Python TFTP library implemented in pure Python. I began this
project after working with TFTP in my workplace. I found that while there
seem to be plenty of command-line tools for TFTP written in Python, there
don't seem to be any good libraries. I'd like to fix that.

Some goals for this project:

* **Support for both Python 2.7 and Python 3.8.** Python 2.7 may be EOL at the
    end of 2019, but I want to maintain support for it for those poor schmucks
    who still have to use it for one reason or another (myself included!).
* **Easy to use.** It should be as simple to set up a client as:
    ```python
    import tftp
    client = tftp.Client("127.0.0.1")
    data = client.get("myfile.txt")
    print(data)
    ```
    But it should also be easy to do more than just the basics. I don't want
    to sacrifice the advanced users just to make basic uses simple.
* **Lightweight.** You shouldn't need to pull in a ton of dependencies into
    your project just to run TFTP.
* **Extensible.** Let's face it: I'm not going to implement every feature that
    everyone will want. I intend to fully support RFC 1350 (the base TFTP
    specification), but there are four other specifications that extend it
    (RFCs 1785, 2347, 2348, and 2349) and many others customizations users may
    want. I can't support everything, but I want to support extending this
    library as best as I can.
* **Well-tested.** There's not much good in a library if it's buggy! I want to
    make sure this library is automatically tested with every commit.
    Unfortunately, I don't have a server to set up CI, but I'll be writing
    lots of automated tests.

Some not-goals for this project:
* **This is not a command-line tool.** There are lots of TFTP tools our there
    to run on the command line or in a UI. To keep the scope of this project
    limited, I only intend to write a library.
* **This does not have all the bells-and-whistles.** The goal here is
    simplicity and light weight.

----

Python TFTP is Copyright (c) 2019 Jennifer Dahm and licensed under the MIT
License. See the LICENSE file alongside this README.