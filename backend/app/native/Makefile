CXX ?= g++
CXXFLAGS ?= -O3 -fPIC -std=c++17 -Wall -Wextra
LDFLAGS ?= -shared

TARGET = libwizard_core.so
SOURCES = wizard_core.cpp

all: $(TARGET)

$(TARGET): $(SOURCES) wizard_core.hpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

.PHONY: all clean
