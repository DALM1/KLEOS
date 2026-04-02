cmake_minimum_required(VERSION 3.10)
project(Kleos LANGUAGES C CXX OBJCXX)

set(CMAKE_OSX_SYSROOT "" CACHE PATH "" FORCE)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenGL REQUIRED)

include_directories(/opt/homebrew/opt/glfw/include)

link_directories(/opt/homebrew/opt/glfw/lib)

set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/imgui)
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
file(GLOB IMGUI_SOURCES
    ${IMGUI_DIR}/*.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

include_directories(${IMGUI_DIR} ${IMGUI_DIR}/backends)

set_source_files_properties(main.cpp ${SRC_DIR}/image_loader.cpp PROPERTIES LANGUAGE OBJCXX)

add_executable(KleosClient main.cpp ${IMGUI_SOURCES} ${SRC_DIR}/image_loader.cpp ${SRC_DIR}/image_loader.h)

target_compile_definitions(KleosClient PRIVATE GL_SILENCE_DEPRECATION)
target_link_options(KleosClient PRIVATE "-Wl,-syslibroot,/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")

target_link_libraries(KleosClient
    glfw
    ${OPENGL_gl_LIBRARY}
    "-framework CoreFoundation"
    "-framework CoreGraphics"
    "-framework ImageIO"
)

add_executable(KleosRelay ${CMAKE_SOURCE_DIR}/relay_server.cpp)
target_link_options(KleosRelay PRIVATE "-Wl,-syslibroot,/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
