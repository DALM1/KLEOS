# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.30

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.30.3/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.30.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/dalm1/Desktop/Reroll/Progra/Kleos

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/dalm1/Desktop/Reroll/Progra/Kleos/build

# Include any dependencies generated for this target.
include CMakeFiles/NetworkMonitoring.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/NetworkMonitoring.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/NetworkMonitoring.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/NetworkMonitoring.dir/flags.make

CMakeFiles/NetworkMonitoring.dir/main.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/main.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/main.cpp
CMakeFiles/NetworkMonitoring.dir/main.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/NetworkMonitoring.dir/main.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/main.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/main.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/main.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/main.cpp

CMakeFiles/NetworkMonitoring.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/main.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/main.cpp > CMakeFiles/NetworkMonitoring.dir/main.cpp.i

CMakeFiles/NetworkMonitoring.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/main.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/main.cpp -o CMakeFiles/NetworkMonitoring.dir/main.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_glfw.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_glfw.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_glfw.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_glfw.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_opengl3.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_opengl3.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_opengl3.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/backends/imgui_impl_opengl3.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_demo.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_demo.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_demo.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_demo.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_draw.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_draw.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_draw.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_draw.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_tables.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_tables.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_tables.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_tables.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.s

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o: CMakeFiles/NetworkMonitoring.dir/flags.make
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o: /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_widgets.cpp
CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o: CMakeFiles/NetworkMonitoring.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Building CXX object CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o -MF CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o.d -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o -c /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_widgets.cpp

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.i"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_widgets.cpp > CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.i

CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.s"
	/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/dalm1/Desktop/Reroll/Progra/Kleos/imgui/imgui_widgets.cpp -o CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.s

# Object files for target NetworkMonitoring
NetworkMonitoring_OBJECTS = \
"CMakeFiles/NetworkMonitoring.dir/main.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o" \
"CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o"

# External object files for target NetworkMonitoring
NetworkMonitoring_EXTERNAL_OBJECTS =

NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/main.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_glfw.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/backends/imgui_impl_opengl3.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/imgui.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/imgui_demo.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/imgui_draw.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/imgui_tables.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/imgui/imgui_widgets.cpp.o
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/build.make
NetworkMonitoring: CMakeFiles/NetworkMonitoring.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_9) "Linking CXX executable NetworkMonitoring"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/NetworkMonitoring.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/NetworkMonitoring.dir/build: NetworkMonitoring
.PHONY : CMakeFiles/NetworkMonitoring.dir/build

CMakeFiles/NetworkMonitoring.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/NetworkMonitoring.dir/cmake_clean.cmake
.PHONY : CMakeFiles/NetworkMonitoring.dir/clean

CMakeFiles/NetworkMonitoring.dir/depend:
	cd /Users/dalm1/Desktop/Reroll/Progra/Kleos/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/dalm1/Desktop/Reroll/Progra/Kleos /Users/dalm1/Desktop/Reroll/Progra/Kleos /Users/dalm1/Desktop/Reroll/Progra/Kleos/build /Users/dalm1/Desktop/Reroll/Progra/Kleos/build /Users/dalm1/Desktop/Reroll/Progra/Kleos/build/CMakeFiles/NetworkMonitoring.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/NetworkMonitoring.dir/depend

