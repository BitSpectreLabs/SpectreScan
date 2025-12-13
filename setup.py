"""
SpectreScan Setup Configuration
by BitSpectreLabs
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    long_description = readme_file.read_text(encoding="utf-8")

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="spectrescan",
    version="3.0.0",
    author="BitSpectreLabs",
    description="Professional-grade port scanner with CLI, TUI, and GUI interfaces",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/BitSpectreLabs/SpectreScan",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Console :: Curses",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "isort>=5.12.0",
        ],
        "full": [
            "scapy>=2.5.0",
            "Jinja2>=3.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "spectrescan=spectrescan.cli.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "spectrescan": [
            "assets/*.txt",
            "assets/*.png",
            "data/*",
            "nse_scripts/*.nse",
        ],
    },
    keywords=[
        "port scanner",
        "network security",
        "penetration testing",
        "security tools",
        "network reconnaissance",
        "vulnerability scanning",
    ],
    project_urls={
        "Bug Reports": "https://github.com/BitSpectreLabs/SpectreScan/issues",
        "Source": "https://github.com/BitSpectreLabs/SpectreScan",
        "Documentation": "https://github.com/BitSpectreLabs/SpectreScan/wiki",
    },
)
