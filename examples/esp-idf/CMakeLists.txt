cmake_minimum_required(VERSION 3.16)
# The library is the component two folders up. A project of your own adds it with: idf.py add-dependency "huelake/connectivitizer"
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../..")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(connectivitizer_example)
