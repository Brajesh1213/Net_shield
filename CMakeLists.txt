cmake_minimum_required(VERSION 3.16)
project(NetSentinel VERSION 0.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Force MinGW to enable threading support
if(MINGW)
    add_compile_options(-std=c++17)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -lpthread")
endif()

# Windows specific
if(WIN32)
    add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600 -DWINVER=0x0600)
    
    # Source files
    set(SOURCES
        main.cpp
        src/core/process_cache.cpp
        src/monitor/file_monitor.cpp
        src/monitor/process_monitor.cpp
        src/network/tcp_table.cpp
        src/network/udp_table.cpp
        src/network/packet_capture.cpp
        src/risk/risk_assessment.cpp
        src/risk/threat_intel.cpp
        src/safety/kill_switch.cpp
        src/safety/firewall_blocker.cpp
        src/utils/logger.cpp
        src/utils/process_verification.cpp
        src/utils/string_utils.cpp
    )
    
    add_executable(NetSentinel ${SOURCES})
    
    # Include directories
    target_include_directories(NetSentinel PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    
    # Link libraries
    target_link_libraries(NetSentinel PRIVATE
        ws2_32        # Winsock
        iphlpapi      # IP Helper API
        psapi         # Process API
        advapi32      # Registry/Security
        shell32       # Shell API
        user32        # Windows UI
        ole32         # COM (for firewall)
        oleaut32      # COM Automation (for firewall)
        wbemuuid      # WMI (for real-time process ETW)
    )

    # YARA Engine configuration
    option(USE_YARA "Enable YARA engine for packet scanning" OFF)
    if(USE_YARA)
        message(STATUS "YARA Engine is ENABLED")
        add_definitions(-DUSE_YARA)
        # Ensure yara headers are in include/ and yara library in lib/
        target_include_directories(NetSentinel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_directories(NetSentinel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib)
        target_link_libraries(NetSentinel PRIVATE yara)
    endif()
    
    # Enable optimizations (MinGW/GCC compatible flags)
    target_compile_options(NetSentinel PRIVATE
        $<$<CONFIG:Release>:-O2 -Wall>
        $<$<CONFIG:Debug>:-O0 -g -Wall>
    )
    
    # Manifest for UAC (optional - for future blocking features)
    # target_sources(NetSentinel PRIVATE NetSentinel.manifest)
endif()
