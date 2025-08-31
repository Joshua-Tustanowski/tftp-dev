cmake_minimum_required(VERSION 3.10)
project(TFTPImplementation)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(tftp_server
    src/main.cpp
    src/tftp_server.cpp
    src/tftp_packet.cpp
)

add_executable(tftp_client
    src/tftp_client.cpp
    src/tftp_packet.cpp
)