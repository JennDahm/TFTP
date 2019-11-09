"""Install script
"""

# To help ensure compatibility between Python 2.7 and Python 3, import these modules.
# See the Google Python Style Guide section 2.20:
# https://google.github.io/styleguide/pyguide.html#220-modern-python-python-3-and-from-__future__-imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import setuptools

# io.open is needed for projects that support Python 2.7
# It ensures open() defaults to text mode with universal newlines,
# and accepts an argument to specify the text encoding
# Python 3 only projects can skip this import
from io import open

with open("README.md", "r", encoding="utf-8") as fd:
    LONG_DESCRIPTION = fd.read()

setuptools.setup(
    # Technical information
    name="tftp",
    version="1.0-a0",
    packages=["tftp"],
    # Basically, 2.7 or >=3.5 (not including a hypothetical Python 4)
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4',

    # Descriptive information
    author="Jennifer Dahm",
    author_email="jdahm@utexas.edu",
    description="A simple TFTP Python library.",
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',  # Others: text/x-rst, text/plain
    url="https://github.com/JennDahm/TFTP",
    project_urls={
        "Bug Reports": "https://github.com/JennDahm/TFTP/issues",
        "Source": "https://github.com/JennDahm/TFTP"
    },
    keywords="tftp network internet",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Internet",
    ],
)
