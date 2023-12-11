cmake_minimum_required(VERSION 3.0.0)
project(Cloud_Storage VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)

include(CTest)
enable_testing()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/client)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/server)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

include_directories(packets)

add_executable(${PROJECT_NAME} main.cpp security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp packets/upload.cpp packets/requestCodes.h)
add_executable(Server server/server.cpp security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp)
add_executable(Client client/Main.cpp  security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp client/Client.h client/Client.cpp)



target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL )
target_link_libraries(Server PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)

target_link_libraries(Client PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
