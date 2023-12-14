cmake_minimum_required(VERSION 3.0.0)
project(Cloud_Storage VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED On)

include(CTest)
enable_testing()

include_directories(client server packets tools security)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(${PROJECT_NAME} main.cpp security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp packets/upload.cpp packets/requestCodes.h tools/file.cpp)
add_executable(Server server/server.cpp security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp)
add_executable(Client client/Main.cpp  security/Util.cpp security/Diffie-Hellman.cpp security/crypto.cpp client/Client.h client/Client.cpp tools/file.cpp )



target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL stdc++fs)
target_link_libraries(Server PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
target_link_libraries(Client PUBLIC OpenSSL::Crypto OpenSSL::SSL Threads::Threads stdc++fs)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
