#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

import setuptools
import BiliDrive

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    install_requires = fh.read().splitlines()

setuptools.setup(
    name="BiliDrive",
    version=BiliDrive.__version__,
    url="https://github.com/Hsury/BiliDrive",
    author=BiliDrive.__author__,
    author_email=BiliDrive.__email__,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: Chinese (Simplified)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Topic :: Communications :: File Sharing",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Utilities",
    ],
    description="☁️ 哔哩哔哩云，支持任意文件的全速上传与下载",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=[
        "bilibili",
        "cloud",
        "disk",
        "drive",
        "storage",
        "pan",
        "yun",
        "B站",
        "哔哩哔哩",
        "网盘",
        "云",
    ],
    install_requires=install_requires,
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            "BiliDrive=BiliDrive.__main__:main",
        ],
    },
    packages=setuptools.find_packages(),
)
