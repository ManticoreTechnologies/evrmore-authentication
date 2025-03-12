from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="evrmore-authentication",
    version="0.3.0",
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
    python_requires=">=3.7",
    install_requires=[
        "evrmore-rpc>=0.1.0",
        "pyjwt>=2.3.0",
        "cryptography>=36.0.0",
        "fastapi>=0.75.0",
        "uvicorn>=0.17.0",
        "python-dotenv>=0.19.0",
        "pydantic>=1.9.0",
    ],
    entry_points={
        "console_scripts": [
            "evrmore-auth-api=evrmore_authentication:run_api_main",
        ],
    },
) 