#
# Copyright 2021-2024 Software Radio Systems Limited
#
# This file is part of srsRAN
#
# srsRAN is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# srsRAN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# A copy of the GNU Affero General Public License can be found in
# the LICENSE file in the top-level directory of this distribution
# and at http://www.gnu.org/licenses/.
#

# - Try to find usrsctp
#
# Once done this will define
#  USRSCTP_FOUND        - System has user plane SCTP library
#  USRSCTP_INCLUDE_DIRS - The user plane SCTP include directories
#  USESCTP_LIBRARIES    - The user plane SCTP library

FIND_PACKAGE(PkgConfig REQUIRED)
PKG_CHECK_MODULES(PC_USRSCTP usrsctp)

FIND_PATH(
    USRSCTP_INCLUDE_DIRS
    NAMES usrsctp.h
    HINTS ${PC_USRSCTP_INCLUDEDIR}
          ${CMAKE_INSTALL_PREFIX}/include
    PATHS /usr/local/include
          /usr/include
)

FIND_LIBRARY(
    USRSCTP_LIBRARIES
    NAMES usrsctp
    HINTS ${PC_SCTP_LIBDIR}
          ${CMAKE_INSTALL_PREFIX}/lib
          ${CMAKE_INSTALL_PREFIX}/lib64
    PATHS /usr/local/lib
          /usr/local/lib64
          /usr/lib
          /usr/lib64
          /usr/lib/x86_64-linux-gnu/
)

message(STATUS "USRSCTP LIBRARIES: " ${SCTP_LIBRARIES})
message(STATUS "USRSCTP INCLUDE DIRS: " ${SCTP_INCLUDE_DIRS})

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(USRSCTP DEFAULT_MSG USRSCTP_LIBRARIES USRSCTP_INCLUDE_DIRS)
MARK_AS_ADVANCED(USRSCTP_LIBRARIES USRSCTP_INCLUDE_DIRS)
