from setuptools import setup, find_packages

setup(
    name="bitcoinpqc",
    version="0.1.0",
    packages=find_packages(),
    description="Python bindings for libbitcoinpqc",
    long_description=open("../README.md").read(),
    long_description_content_type="text/markdown",
    author="Bitcoin PQC Developers",
    url="https://github.com/bitcoinpqc/libbitcoinpqc",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.7",
)
