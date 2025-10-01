cmake_minimum_required(VERSION 3.15)
project(ffplay_clone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
find_package(sdl2 CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

if(PKG_CONFIG_FOUND)
    pkg_check_modules(AVCODEC REQUIRED libavcodec)
    pkg_check_modules(AVFORMAT REQUIRED libavformat)
    pkg_check_modules(AVUTIL REQUIRED libavutil)
    pkg_check_modules(SWSCALE REQUIRED libswscale)
    pkg_check_modules(AVFILTER REQUIRED libavfilter)
    pkg_check_modules(SWRESAMPLE REQUIRED libswresample)
endif()

add_executable(ffplay_clone
    src/main.cpp
)

target_link_libraries(ffplay_clone
    ${AVCODEC_LIBRARIES}
    ${AVFORMAT_LIBRARIES}
    ${AVUTIL_LIBRARIES}
    ${SWSCALE_LIBRARIES}
    ${AVFILTER_LIBRARIES}
    ${SWRESAMPLE_LIBRARIES}
    SDL2::SDL2
    SDL2::SDL2main
    spdlog::spdlog
)

target_include_directories(ffplay_clone PRIVATE
    ${AVCODEC_INCLUDE_DIRS}
    ${AVFORMAT_INCLUDE_DIRS}
    ${AVUTIL_INCLUDE_DIRS}
    ${SWSCALE_INCLUDE_DIRS}
    ${AVFILTER_INCLUDE_DIRS}
    ${SWRESAMPLE_INCLUDE_DIRS}
)
