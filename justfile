# version
version := '2.2.0'

# variables
cc := 'g++'
cd := 'gdb'
ct := 'valgrind'
c-standard := 'c++17'
c-common-flags := '-std=' + c-standard + ' -pedantic -W -Wall -Wextra -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -I./src/h'
c-release-flags := c-common-flags + ' -Werror -O2'
c-debug-flags := c-common-flags + ' -O1 -g'
c-extra-flags := ''

# rules
os-build-dir := './build/' + os()
project-name := 'password_manager'

_validate mode:
    @ if [ '{{ mode }}' != 'debug' ] && [ '{{ mode }}' != 'release' ]; then echo '`mode` must be: `debug` or `release`, not `{{ mode }}`'; exit 1; fi

# build project (mode must be: debug or release)
build mode:
    just _validate {{mode}}
    mkdir -p "{{os-build-dir}}/{{project-name}}"
    just _build_{{mode}}

_build_debug:
    {{cc}} {{c-debug-flags}} src/cpp/menu.cpp src/cpp/pass_gen.cpp src/cpp/crypto.cpp src/cpp/exceptions.cpp src/cpp/database.cpp src/cpp/totp.cpp src/cpp/mmap_utils.cpp src/cpp/import_export.cpp -o "{{os-build-dir}}/{{project-name}}/debug" -L/usr/lib64 -lssl -lcrypto -ldl -lsqlite3 -loath -ljsoncpp

_build_release:
    {{cc}} {{c-release-flags}} src/cpp/menu.cpp src/cpp/pass_gen.cpp src/cpp/crypto.cpp src/cpp/exceptions.cpp src/cpp/database.cpp src/cpp/totp.cpp src/cpp/mmap_utils.cpp src/cpp/import_export.cpp -o "{{os-build-dir}}/{{project-name}}/release" -L/usr/lib64 -lssl -lcrypto -ldl -lsqlite3 -loath -ljsoncpp

# execute project's binary (mode must be: debug or release)
run mode *args:
    just build {{mode}}
    "{{os-build-dir}}/{{project-name}}/{{mode}}" {{args}}

# start debugger
debug:
    just build debug
    {{cd}} "{{os-build-dir}}/{{project-name}}/debug"

# clean project's build directory
clean:
    rm -rf "{{os-build-dir}}"

# run a memory error detector valgrind
test mode *args:
    just build {{mode}}
    {{ct}} --leak-check=full --show-leak-kinds=all --track-origins=yes "{{os-build-dir}}/{{project-name}}/{{mode}}" {{args}}
