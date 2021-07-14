cmake_minimum_required(VERSION 3.20)

project(tls13)

add_executable(client client.cpp)
target_link_libraries(client crypto ssl)

add_executable(server server.cpp)
target_link_libraries(server crypto ssl)