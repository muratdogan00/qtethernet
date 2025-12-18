cmake_minimum_required(VERSION 3.19)
project(untitled3 LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)

qt_standard_project_setup()

qt_add_executable(untitled3
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

target_link_libraries(untitled3
    PRIVATE
        Qt::Core
        Qt::Widgets
        Qt::Network

)
set(NPCAP_SDK "D:/Dev/npcap-sdk-1.15")

# Header (pcap.h)
target_include_directories(untitled3 PRIVATE
    "${NPCAP_SDK}/Include"
)

# Libraries (wpcap.lib, Packet.lib) - x64
target_link_directories(untitled3 PRIVATE
    "${NPCAP_SDK}/Lib/x64"
)

# Link required libs
target_link_libraries(untitled3 PRIVATE
    wpcap
    Packet
    Ws2_32
    Iphlpapi
)

include(GNUInstallDirs)

install(TARGETS untitled3
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET untitled3
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
