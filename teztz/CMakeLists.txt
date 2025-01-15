# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.10)

project ("teztz")

# see https://learn.microsoft.com/en-us/vcpkg/get_started/get-started?pivots=shell-powershell for vcpkg setup
# and catch2 documentation https://github.com/catchorg/Catch2/blob/devel/docs/cmake-integration.md
# and https://cmake.org/cmake/help/book/mastering-cmake/chapter/Converting%20Existing%20Systems%20To%20CMake.html for updates
find_package(Catch2 3 REQUIRED)
# These tests can use the Catch2-provided main

#set(SOURCE_FILES 
#    main.cpp 
#    utils.cpp 
#    other_file.cpp
#)

# Link the library to the executable
#target_link_libraries(myexe PRIVATE mylib)

# Include the library's header files
#target_include_directories(myexe PRIVATE include)

file(GLOB test_src_files CONFIGURE_DEPENDS "*.h" "*.cpp")
add_executable(tests ${test_src_files})
#file(GLOB tsk_lib CONFIGURE_DEPENDS "../win32/x64/Release/libtsk.lib")
file(GLOB tsk_libs CONFIGURE_DEPENDS "*.h" "*.cpp")

# Your-external "mylib", add GLOBAL if the imported library is located in directories above the current.
# add_library( tsk_lib SHARED IMPORTED )
# You can define two import-locations: one for debug and one for release.
# set_target_properties( tsk_lib PROPERTIES IMPORTED_LOCATION ${test_obj_file_dirs} )

target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)
target_include_directories(tests PRIVATE ../)
target_link_directories(tests BEFORE PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../win32/x64/Release")

# include(CTest)
# include(Catch)
# catch_discover_tests(tests)



# These tests need their own main
# add_executable(custom-main-tests test.cpp test-main.cpp)
#target_link_libraries(custom-main-tests PRIVATE Catch2::Catch2)


# Add source to this project's executable.
#add_executable (teztz "teztz.cpp" "teztz.h")

# TODO: Add tests and install targets if needed.