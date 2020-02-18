# Python TFTP

This is a Python TFTP library implemented in pure Python. I began this
project after working with TFTP in my workplace. I found that while there
seem to be plenty of command-line tools for TFTP written in Python, there
don't seem to be any good libraries. I'd like to fix that.

Some goals for this project:

* **Support for both Python 2.7 and Python 3.7.** Python 2.7 may be EOL at the
    end of 2019, but I want to maintain support for it for those poor souls
    who still have to use it for one reason or another (myself included!).
* **Easy to use.** It should be (approximately) as simple to set up a client as:
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
* **Complete.** I intend to fully support RFC 1350 (the base TFTP specification)
    and the most common extensions (RFC 2347 "TFTP Option Extension", RFC 2348
    "TFTP Blocksize Option", RFC 2349 "TFTP Timeout Interval and Transfer Size
    Options", and RFC 7440 "TFTP Windowsize Option").
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

Python TFTP is Copyright (c) 2019-2020 Jennifer Dahm and licensed under the MIT
License. See the LICENSE file alongside this README.