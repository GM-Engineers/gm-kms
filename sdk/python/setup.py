from setuptools import setup, find_packages

setup(
    name="gmsdk",
    version="0.1.0",
    description="GM-KMS Python SDK",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GM-KMS Team",
    author_email="kms@example.com",
    url="https://github.com/GM-Engineers/gm-kms",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
