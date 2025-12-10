CXX = g++
CXXFLAGS = -std=c++17 -Wall -O2
LIBS = -lboost_system -lpthread

TARGET = NewWinAppApp
SRC_DIR = NewWinApp
SOURCES = $(SRC_DIR)/main.cpp $(SRC_DIR)/SystemInfo_Linux.cpp
OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
