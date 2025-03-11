from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evrmore-authentication",
    version="0.1.0",
    author="Manticore Technologies",
    author_email="dev@manticore.technology",
    description="Authentication system using Evrmore blockchain signatures",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/manticoretechnologies/evrmore-authentication",
    project_urls={
        "Documentation": "https://manticoretechnologies.github.io/evrmore-authentication/",
        "Bug Tracker": "https://github.com/manticoretechnologies/evrmore-authentication/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=[
        "evrmore-rpc",
        "psycopg2-binary>=2.9.3",
        "sqlalchemy>=1.4.0",
        "alembic>=1.7.5",
        "pyjwt>=2.3.0",
        "cryptography>=36.0.0",
        "fastapi>=0.75.0",
        "passlib>=1.7.4",
    ],
    entry_points={
        "console_scripts": [
            "evrmore-auth=evrmore_authentication.cli:main",
        ],
    },
) 