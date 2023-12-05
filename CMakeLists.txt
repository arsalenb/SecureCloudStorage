cmake_minimum_required(VERSION 3.0.0)
project(Cloud_Storage VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Client)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Server)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
add_executable(Server Server/server.cpp Util.cpp Diffie-Hellman.cpp crypto.cpp)
add_executable(Client Client/client.cpp Util.cpp Diffie-Hellman.cpp crypto.cpp)

target_include_directories(Server PRIVATE data)

target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(Server PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
target_link_libraries(Client PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
