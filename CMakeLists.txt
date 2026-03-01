cmake_minimum_required(VERSION 3.16)
project(Asthak VERSION 0.3.0 LANGUAGES CXX)

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
    add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0601 -DWINVER=0x0601)
    
    set(SOURCES
        main.cpp
        src/core/process_cache.cpp
        src/monitor/file_monitor.cpp
        src/monitor/process_monitor.cpp
        src/monitor/registry_monitor.cpp
        src/network/tcp_table.cpp
        src/network/udp_table.cpp
        src/network/packet_capture.cpp
        src/network/wfp_manager.cpp
        src/risk/risk_assessment.cpp
        src/risk/threat_intel.cpp
        src/risk/hash_scanner.cpp
        src/risk/pe_analyzer.cpp
        src/risk/dns_analyzer.cpp
        src/risk/vt_lookup.cpp
        src/safety/kill_switch.cpp
        src/safety/firewall_blocker.cpp
        src/safety/self_protection.cpp
        src/safety/ransomware_guard.cpp
        src/safety/response_engine.cpp
        src/safety/quarantine.cpp
        src/safety/amsi_scanner.cpp
        src/telemetry/etw_consumer.cpp
        src/utils/logger.cpp
        src/utils/process_verification.cpp
        src/utils/string_utils.cpp
    )
    
    add_executable(Asthak ${SOURCES})
    
    # Include directories
    target_include_directories(Asthak PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    
    # User-Mode API Hook DLL
    add_library(Asthak_Hook SHARED src/hooks/asthak_hook.cpp)
    target_link_libraries(Asthak_Hook PRIVATE kernel32 user32)
    # Ensure it's built next to the Asthak executable
    set_target_properties(Asthak_Hook PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
    
    # Link libraries
    target_link_libraries(Asthak PRIVATE
        ws2_32        # Winsock
        iphlpapi      # IP Helper API
        psapi         # Process API
        advapi32      # Registry/Security/ETW StartTrace
        shell32       # Shell API
        user32        # Windows UI
        ole32         # COM (for firewall)
        oleaut32      # COM Automation (for firewall)
        wbemuuid      # WMI (for real-time process events)
        tdh           # Trace Data Helper (for ETW event parsing)
        bcrypt        # SHA-256 hashing (CNG API)
        wininet       # WinINet (for VirusTotal API HTTPS requests)
        fwpuclnt      # Windows Filtering Platform (WFP)
    )

    # YARA Engine configuration
    # YARA is the industry-standard malware pattern matching engine.
    # To enable: download yara from https://github.com/VirusTotal/yara
    #   1. Build yara for MinGW: ./configure && make
    #   2. Copy libyara.a to rp/lib/
    #   3. Copy yara/*.h to rp/include/yara/
    # Re-run cmake with -DUSE_YARA=ON or toggle it here:
    option(USE_YARA "Enable YARA engine for malware pattern matching" OFF)
    if(USE_YARA)
        message(STATUS "YARA Engine is ENABLED")
        add_definitions(-DUSE_YARA)
        target_include_directories(Asthak PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_directories(Asthak PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib)
        target_link_libraries(Asthak PRIVATE yara crypto)
        message(STATUS "YARA: link yara + crypto from lib/")
    else()
        message(STATUS "YARA Engine is DISABLED (build with -DUSE_YARA=ON to enable)")
    endif()
    
    # Enable optimizations (MinGW/GCC compatible flags)
    target_compile_options(Asthak PRIVATE
        $<$<CONFIG:Release>:-O2 -Wall>
        $<$<CONFIG:Debug>:-O0 -g -Wall>
    )
    
    # Manifest for UAC (optional - for future blocking features)
    # target_sources(Asthak PRIVATE Asthak.manifest)
endif()
