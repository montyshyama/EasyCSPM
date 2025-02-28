from setuptools import setup, find_packages

setup(
    name="easy_cspm",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.24.0",
        "python-dotenv>=0.20.0",
        "sqlalchemy>=1.4.0",
    ],
    entry_points={
        "console_scripts": [
            "easy-cspm=easy_cspm.cli:main",
        ],
    },
) 