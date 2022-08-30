#
# This file was taken from RakNet 4.082.
# Please see licenses/RakNet license.txt for the underlying license and related copyright.
#
#
# Modified work: Copyright (c) 2017-2019, SLikeSoft UG (haftungsbeschränkt)
#
# This source code was modified by SLikeSoft. Modifications are licensed under the MIT-style
# license found in the license.txt file in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.12)

set(SLIKENET_INTERNAL_INCLUDE_DIRS 
	${SLikeNet_SOURCE_DIR}/Source/include
	${SLikeNet_SOURCE_DIR}/DependentExtensions
)

if(SLIKENET_ENABLE_STATIC)
	add_subdirectory(LibStatic)
endif()

if(SLIKENET_ENABLE_DLL)
	add_subdirectory(DLL)
endif()
