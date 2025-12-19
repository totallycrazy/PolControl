from pathlib import Path
from setuptools import setup


README = Path(__file__).with_name("README.md").read_text(encoding="utf-8") if Path(__file__).with_name("README.md").exists() else "Polkit Manager Pro"


setup(
    name="polcontrol",
    version="0.1.0",
    description="Desktop utility for managing Polkit rules with a GTK interface",
    long_description=README,
    long_description_content_type="text/markdown",
    author="PolControl",
    python_requires=">=3.8",
    py_modules=["main", "logic", "helper"],
    include_package_data=True,
    entry_points={"console_scripts": ["polcontrol=main:main"]},
    install_requires=["pygobject"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Environment :: X11 Applications :: GTK",
    ],
    package_data={"": ["org.example.polkit-editor.policy"]},
)
