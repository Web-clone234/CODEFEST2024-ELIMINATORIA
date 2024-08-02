CXX = g++
CXXFLAGS = -std=c++11
LDFLAGS = -Lcryptopp
LIBFLAG = -lcryptopp
INCLUDES = -Icryptopp
LIBDIR = cryptopp
SOURCES = $(foreach D, $(LIBDIR), $(wildcard $(D)/*.cpp))
OBJECTS = $(patsubst %.cpp, %.o, $(SOURCES))
EXECUTABLE = main

all: $(EXECUTABLE)

$(EXECUTABLE): cryptopp/libcryptopp.a
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LDFLAGS) -o $(EXECUTABLE) main.cpp $(LIBFLAG)

cryptopp/libcryptopp.a: $(OBJECTS)
	ar rcs cryptopp/libcryptopp.a $(OBJECTS)

$(LIBDIR)/%.o: $(LIBDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -DCRYPTOPP_DISABLE_ASM=1 -DCRYPTOPP_DISABLE_AESNI=1 -DCRYPTOPP_DISABLE_SHANI=1 -O2 -c $< -o $@
