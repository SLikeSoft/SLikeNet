#
# This file was taken from RakNet 4.082.
# Please see licenses/RakNet license.txt for the underlying license and related copyright.
#
#
# Modified work: Copyright (c) 2016-2019, SLikeSoft UG (haftungsbeschränkt)
#
# This source code was modified by SLikeSoft. Modifications are licensed under the MIT-style
# license found in the license.txt file in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.12)

# CMake policy settings
if( POLICY CMP0037 )
	cmake_policy(SET CMP0037 NEW) # CMake 3.0 warning: Target names should not be reserved and should match a validity pattern (aka: add_*-command target names)
endif()
if( POLICY CMP0042 )
	cmake_policy(SET CMP0042 NEW) # CMake 3.0 warning: Use @rpath in a target's install name.
endif()
cmake_policy(SET CMP0048 NEW)

project(SLikeNet VERSION 0.2.0)

set(SLikeNet_API_VERSION ${SLikeNet_VERSION_MAJOR}.${SLikeNet_VERSION_MINOR})

# explicitly enable @rpath in the install name for any shared library being built (for cmake >=2.8.12 and <3.0 - it's enabled by default for >= 3.0)
# note that for cmake < 2.8.12 we do not use rpath but rather keep the RakNet 4.082 behavior
if( CMAKE_VERSION VERSION_LESS 3.0 )
	if(NOT (CMAKE_VERSION VERSION_LESS 2.8.12))
		# MACOSX_RPATH support was added in cmake 2.8.12
		set(CMAKE_MACOSX_RPATH 1)
	endif()
endif()

IF (WIN32 AND NOT UNIX)
	set (PROGRAMFILESX86 $ENV{PROGRAMFILES})
	string(REPLACE "\\" "/" PROGRAMFILESX86 "${PROGRAMFILESX86}")
ENDIF(WIN32 AND NOT UNIX)

# add package dependencies
find_package(OpenSSL 1.0.0 REQUIRED)
set(SLIKENET_LIBRARY_LIBS OpenSSL::Crypto OpenSSL::SSL)

IF (WIN32 AND NOT UNIX)
	set(SLIKENET_LIBRARY_LIBS ${SLIKENET_LIBRARY_LIBS} ws2_32.lib)
ELSE(WIN32 AND NOT UNIX)
	set(SLIKENET_LIBRARY_LIBS ${SLIKENET_LIBRARY_LIBS} pthread)
ENDIF(WIN32 AND NOT UNIX)

# enable C++11 language support for GCC
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
else()
    message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

# options
IF (WIN32 AND NOT UNIX)
	option(SLIKENET_ENABLE_SAMPLES "Generate sample projects if true."                 TRUE)
ELSE (WIN32 AND NOT UNIX)
	# building samples is disabled atm by default on Unix/Mac, since the sample projects won't compile correctly
	option(SLIKENET_ENABLE_SAMPLES "Generate sample projects if true."                 FALSE)
ENDIF(WIN32 AND NOT UNIX)
option(SLIKENET_ENABLE_DLL         "Generate the DLL / shared object project if true." TRUE)
option(SLIKENET_ENABLE_STATIC      "Generate the static library project if true."      TRUE)

set(SLIKENET_HEADER_FILES ${SLikeNet_SOURCE_DIR}/Source)

include(./CmakeIncludes/CmakeMacros.txt)
FIXLINKOPTIONS()
FIXCOMPILEOPTIONS()

add_subdirectory(Lib)

set(SLIKENET_COMMON_LIBS SLikeNetLibStatic)

if(SLIKENET_ENABLE_SAMPLES)
	add_subdirectory(Samples)
endif()
