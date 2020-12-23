from setuptools import setup, find_packages

setup(
    name="MaliciousDetection",
    version="1.0",
    packages=find_packages(where="src", exclude=("test",)),
    package_dir={"": "src"},
    entry_points="""\
    [console_scripts]
    malware-detection = cli:cli
    """
)

