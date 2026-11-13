from setuptools import setup, find_packages

setup(
    name="quantumpulse",
    version="1.0.0",
    description="CBOM File Analyzer & NIST Post-Quantum Cryptography Migration Advisor",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "typer>=0.12.0",
        "rich>=13.7.0",
        "streamlit>=1.35.0",
        "plotly>=5.22.0",
        "reportlab>=4.2.0",
        "jsonschema>=4.22.0",
        "pydantic>=2.7.0",
        "pyyaml>=6.0.1",
        "pandas>=2.2.0",
    ],
    entry_points={
        "console_scripts": [
            "quantumpulse=cli.main:app",
        ],
    },
)

