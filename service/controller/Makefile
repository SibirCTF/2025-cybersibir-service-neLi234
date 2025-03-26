CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude -Isqlite
LDFLAGS = -lpthread -ldl

# Directory structure
SRC_DIR = src
INCLUDE_DIR = include
SQLITE_DIR = sqlite
BUILD_DIR = build

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))
EXECUTABLE = $(BUILD_DIR)/server

# SQLite files
SQLITE_SOURCE = $(SQLITE_DIR)/sqlite3.c
SQLITE_OBJECT = $(BUILD_DIR)/sqlite3.o

# Default target
all: $(EXECUTABLE)

# Link main executable
$(EXECUTABLE): $(OBJECTS) $(SQLITE_OBJECT)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Compile C++ sources
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile SQLite
$(SQLITE_OBJECT): $(SQLITE_SOURCE) | $(BUILD_DIR)
	$(CC) -c $< -o $@ -fPIC

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean