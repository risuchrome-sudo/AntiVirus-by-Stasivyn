from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension(
        "engine.Updater.database_updater",
        ["engine/Updater/database_updater.py"]
    )
]

setup(
    name="antivirus-engine",
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3"}
    )
)
