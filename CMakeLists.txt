cmake_minimum_required(VERSION 3.10)
project(NetworkMonitoring)

set(CMAKE_CXX_STANDARD 11)

# Trouver OpenGL
find_package(OpenGL REQUIRED)

# Chemins spécifiques pour GLFW
include_directories(/opt/homebrew/opt/glfw/include)

# Ajouter le chemin pour les bibliothèques
link_directories(/opt/homebrew/opt/glfw/lib)

# Inclure les fichiers source d'ImGui
set(IMGUI_DIR ${CMAKE_SOURCE_DIR}/imgui)
file(GLOB IMGUI_SOURCES
    ${IMGUI_DIR}/*.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

include_directories(${IMGUI_DIR} ${IMGUI_DIR}/backends)

# Ajouter l'exécutable
add_executable(NetworkMonitoring main.cpp ${IMGUI_SOURCES})

# Lier GLFW, OpenGL et ImGui
target_link_libraries(NetworkMonitoring
    glfw
    ${OPENGL_gl_LIBRARY}
)
