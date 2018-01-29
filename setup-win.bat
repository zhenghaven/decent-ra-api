@echo off

IF NOT EXIST build (
	MKDIR build
	ECHO Create build directory...
)

PUSHD build
ECHO in build directory...
cmake ../  -G "Visual Studio 14 2015"
POPD

PAUSE