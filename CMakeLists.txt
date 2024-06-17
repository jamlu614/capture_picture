cmake_minimum_required(VERSION 3.10.0)
project(capture_picture VERSION 0.1.0 LANGUAGES C CXX)

add_executable(capture_picture main.cpp)
target_link_libraries(
    ${PROJECT_NAME}
    v4l2
    ssl
    crypto
    mosquitto
)
