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

cmake_policy(SET CMP0048 NEW)

project(SLikeNetLibStatic VERSION ${SLikeNet_VERSION})

FILE(GLOB ALL_HEADER_SRCS ${SLikeNet_SOURCE_DIR}/Source/include/slikenet/*.h)
FILE(GLOB ALL_COMPATIBILITY_HEADER_SRC ${SLikeNet_SOURCE_DIR}/Source/*.h)
FILE(GLOB ALL_COMPATIBILITY_HEADER_SRC_2 ${SLikeNet_SOURCE_DIR}/Source/slikenet/*.h)
FILE(GLOB ALL_CPP_SRCS ${SLikeNet_SOURCE_DIR}/Source/src/*.cpp)
FILE(GLOB CRYPTO_CPP_SRCS ${SLikeNet_SOURCE_DIR}/Source/src/crypto/*.cpp)

add_library(SLikeNetLibStatic STATIC ${ALL_CPP_SRCS} ${CRYPTO_CPP_SRCS} ${ALL_HEADER_SRCS})

include_directories(${SLIKENET_INTERNAL_INCLUDE_DIRS})

# set the version number
set_target_properties(SLikeNetLibStatic PROPERTIES
	SOVERSION ${SLikeNet_API_VERSION}
)

# by default we build the retail configuration
add_definitions(-D_RETAIL)

IF(WIN32 AND NOT UNIX)
	add_definitions(-DWIN32 -D_RAKNET_DLL -D_CRT_NONSTDC_NO_DEPRECATE -D_CRT_SECURE_NO_DEPRECATE)
	SET( CMAKE_CXX_FLAGS "/GS- /GR-" )
ELSE(WIN32 AND NOT UNIX)
	set_target_properties(SLikeNetLibStatic PROPERTIES
		OUTPUT_NAME "slikenet"
	)
ENDIF(WIN32 AND NOT UNIX)

target_link_libraries(SLikeNetLibStatic ${SLIKENET_LIBRARY_LIBS})
IF(WIN32 AND NOT UNIX)
	IF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")
		set_target_properties(SLikeNetLibStatic PROPERTIES STATIC_LIBRARY_FLAGS "/NODEFAULTLIB:\"LIBCD.lib LIBCMTD.lib MSVCRT.lib\"" )
	ENDIF(NOT ${CMAKE_GENERATOR} STREQUAL "MSYS Makefiles")
ELSE(WIN32 AND NOT UNIX)
	configure_file(../../slikenet-config-version.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/slikenet-config-version.cmake @ONLY)

	INSTALL(TARGETS SLikeNetLibStatic EXPORT SLikeNetLibStatic DESTINATION lib/slikenet-${SLikeNet_VERSION})
	INSTALL(FILES ${ALL_COMPATIBILITY_HEADER_SRC} DESTINATION include/slikenet-${SLikeNet_VERSION})
	INSTALL(FILES ${ALL_COMPATIBILITY_HEADER_SRC_2} DESTINATION include/slikenet-${SLikeNet_VERSION}/slikenet)
	INSTALL(FILES ${ALL_HEADER_SRCS} DESTINATION include/slikenet-${SLikeNet_VERSION}/include/slikenet)
	INSTALL(FILES ../../slikenet-config.cmake ${CMAKE_CURRENT_BINARY_DIR}/slikenet-config-version.cmake DESTINATION lib/slikenet-${SLikeNet_VERSION})
	INSTALL(EXPORT SLikeNetLibStatic FILE slikenet.cmake DESTINATION lib/slikenet-${SLikeNet_VERSION})
ENDIF(WIN32 AND NOT UNIX)
