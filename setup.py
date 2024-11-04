from setuptools import setup, find_packages

setup(
    name="langsec",
    version="0.1.0-alpha",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "sqlglot>=11.5.0",
        "pydantic>=2.0.0",
        "typing-extensions>=4.0.0",
    ],
    tests_require=[
        "pytest>=7.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "isort>=5.0.0",
        ]
    },
    python_requires=">=3.8",
    author="Amit Schendel & Arbel Israeli",
    author_email="dev@lang-sec.com",
    description="Security framework for LLM-generated SQL queries",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/langsec-ai/langsec",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
