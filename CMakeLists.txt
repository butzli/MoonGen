cmake_minimum_required(VERSION 2.8...3.18)
project(MoonGen C CXX)

#Options are defined in libmoon/CMakeLists.txt

set(CMAKE_CXX_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu++11 -march=native -msse4.2")
set(CMAKE_C_FLAGS "-fno-stack-protector -Wall -Wextra -Wno-unused-parameter -g -O3 -std=gnu11 -march=native -msse4.2")
set(CMAKE_EXE_LINKER_FLAGS "-rdynamic")

set(LIBMOON_BUILD_LIBRARY true)
add_definitions(-DLIBMOON_LUA_MAIN_MODULE="moongen-main")
add_subdirectory(libmoon)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/src
	${CMAKE_CURRENT_SOURCE_DIR}/lib
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/deps/dpdk/x86_64-native-linux-gcc/include
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/deps/dpdk/lib/librte_ethdev
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/deps/luajit/src
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/lib
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/src
)

set(files
	src/moongen-main.cpp
	src/software-timestamping.c
	src/software-rate-limiter.cpp
	src/moonsniff.cpp
	src/histogram.cpp
	src/crc-ratecontrol.cpp
	src/launch-timestamp.cpp
	src/moonem_common.c
	src/moonem_sw.cpp
	src/moonem.cpp
	src/ipsec-sw.c
)

set(libraries
	-Wl,--whole-archive moon
	-Wl,--start-group ${dpdk_STATIC_LINK_LIBRARIES} ${dpdk_STATIC_LDFLAGS} ${dpdk_STATIC_LDFLAGS_OTHER} -Wl,--end-group
)

link_directories(
	${dpdk_STATIC_LINK_DIRS}
	${CMAKE_CURRENT_BINARY_DIR}/libmoon
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/deps/dpdk/x86_64-native-linux-gcc/lib
	${CMAKE_CURRENT_SOURCE_DIR}/libmoon/deps/luajit/usr/local/lib
)

add_executable(MoonGen ${files})
target_link_libraries(MoonGen ${libraries})

