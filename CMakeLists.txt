cmake_minimum_required(VERSION 3.10)
project(password_manager)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS -lncursesw)

# Find and link required libraries
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(Curses REQUIRED)
find_package(jsoncpp REQUIRED)

# Define the executable and list all source files
add_executable(password_manager
    src/cpp/main.cpp
    src/cpp/crypto.cpp
    src/cpp/database.cpp
    src/cpp/exceptions.cpp
    src/cpp/import_export.cpp
    src/cpp/mmap_utils.cpp
    src/cpp/pass_gen.cpp
    src/cpp/totp.cpp
    src/cpp/tui.cpp
)

# Link libraries to the executable
target_link_libraries(password_manager
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    ${CURSES_LIBRARIES}
    jsoncpp
    oath  # For liboath; may need manual linking if no find_package exists
)