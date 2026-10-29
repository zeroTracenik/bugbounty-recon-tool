from setuptools import setup, find_packages

setup(
    name="subpulse",
    version="1.0.0",
    description="High-Speed Subdomain Discovery & Intelligence Engine",
    author="SubPulse Core Team",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "subpulse": ["wordlists/*.txt"],
    },
    install_requires=[
        "aiohttp>=3.9.0",
        "dnspython>=2.6.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "subpulse=subpulse.cli:main",
        ],
    },
    python_requires=">=3.8",
)
