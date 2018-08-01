TARGET_TEST ?= blstest
TARGET_BENCH ?= blsbench

SRC_DIRS ?= ./src ./lib/relic/include ./lib/relic/relic-target/include ./lib/catch ./lib/libsodium-1.0.16/src/libsodium/include
SRCS_TEST := $(shell find $(SRC_DIRS) -name *.c -or ! \( ! -name *.cpp -or -name test-bench.cpp \) )
SRCS_BENCH := $(shell find $(SRC_DIRS) -name *.c -or ! \( ! -name *.cpp -or -name test.cpp \) )
OBJS_TEST := $(addsuffix .o,$(basename $(SRCS_TEST)))
OBJS_BENCH := $(addsuffix .o,$(basename $(SRCS_BENCH)))

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
LIBS = -L ./lib/relic/relic-target/lib -lrelic_s \
       -L ./lib/libsodium-1.0.16/src/libsodium/.libs -lsodium -lsodium.23 \
	   -L ./lib/gmp-6.1.2/.libs -lgmp

CPP = g++
CPPFLAGS ?= $(INC_FLAGS) -std=c++11 -Wall -pedantic -g

$(TARGET_TEST): $(OBJS_TEST)
	$(CPP) $(LIBS) -o $(TARGET_TEST) $(OBJS_TEST)

$(TARGET_BENCH): $(OBJS_BENCH)
	$(CPP) $(LIBS) -o $(TARGET_BENCH) $(OBJS_BENCH)

%o: %.cpp
	$(MKDIR_P) $(dir $@)
	$(CPP) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

test: blstest
	./blstest -d yes

bench: blsbench
	./blsbench -d yes

cleantest: clean blstest
	./blstest -d yes

cleanbench: clean blsbench
	./blsbench -d yes

clean:
	rm -rf $(TARGET_TEST) $(TARGET_BENCH) $(OBJS_TEST) $(OBJS_BENCH)
