cmake_minimum_required (VERSION 2.8 FATAL_ERROR)
project (gluster-nbd C)
set(VERSION 0.1)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wdeclaration-after-statement -std=c99")

include(GNUInstallDirs)
include(CheckIncludeFile)

set(gluster_nbd_HANDLER_PATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/gluster-nbd")

find_library(LIBNL_LIB nl-3)
find_library(LIBNL_GENL_LIB nl-genl-3)
set(LIBNL_LIBS
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  )

find_path (LIBNL_INCLUDE_DIR
  NAMES
  netlink/netlink.h
  PATH_SUFFIXES
  libnl3
  )

find_library(GFAPI gfapi)

find_package(PkgConfig)
pkg_check_modules(GLIB REQUIRED gio-unix-2.0)
pkg_check_modules(KMOD REQUIRED libkmod)

find_library(PTHREAD pthread)
find_library(DL dl)

# Stuff for building the main binary
add_executable(gluster-nbd
  main.c
  )
target_include_directories(gluster-nbd
  PUBLIC ${PROJECT_BINARY_DIR}
  PUBLIC ${GLIB_INCLUDE_DIRS}
  PUBLIC ${KMOD_INCLUDE_DIRS}
  PUBLIC ${LIBNL_INCLUDE_DIR}
  )
target_link_libraries(gluster-nbd
  ${LIBNL_LIB}
  ${LIBNL_GENL_LIB}
  ${GLIB_LIBRARIES}
  ${PTHREAD}
  ${DL}
  ${GFAPI}
  ${KMOD_LIBRARIES}
  -Wl,--no-export-dynamic
  )
install(TARGETS gluster-nbd RUNTIME DESTINATION bin)

install(TARGETS RUNTIME DESTINATION bin)

add_custom_target(
  cscope
  COMMAND find -name '*.[ch]' > cscope.files
  COMMAND cscope -bq
  )
set_directory_properties(
  PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES
  "cscope.files;cscope.in.out;cscope.out;cscope.po.out"
  )
