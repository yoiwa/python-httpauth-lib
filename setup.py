#!/usr/bin/python3
import setuptools
import os
with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
    name="python-httpauth-lib",
#    version="0.1",
    author="Yutaka OIWA",
    author_email="y.oiwa@aist.go.jp",
    description="Library for extended HTTP Authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="Apache License, Version 2.0",
    url="https://github.com/yoiwa/python-httpauth-lib/",
    packages=['http_auth'],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ),
)
