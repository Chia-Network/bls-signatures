TARGET_TEST ?= blstest
TARGET_BENCH ?= blsbench
TMPFILE  = libbls1.a
OUTPUTFILE  = libbls.a

SRC_DIRS ?= ./include ./src ./lib/catch ./lib/libsodium-1.0.16/src/libsodium/include
SRCS_BIN := $(shell find $(SRC_DIRS) -name *.c -or ! \( ! -name *.cpp -or -name test-bench.cpp  -or -name test.cpp \) )
SRCS_TEST := $(shell find $(SRC_DIRS) -name *.c -or ! \( ! -name *.cpp -or -name test-bench.cpp \) )
SRCS_BENCH := $(shell find $(SRC_DIRS) -name *.c -or ! \( ! -name *.cpp -or -name test.cpp \) )
OBJS_BIN := $(addsuffix .o,$(basename $(SRCS_BIN)))
OBJS_TEST := $(addsuffix .o,$(basename $(SRCS_TEST)))
OBJS_BENCH := $(addsuffix .o,$(basename $(SRCS_BENCH)))

INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))
LIBS = -L ./lib/relic/relic-target/lib -lrelic_s \
       -L ./lib/libsodium-1.0.16/src/libsodium/.libs -lsodium -lsodium.23 \
	   -L ./lib/gmp-6.1.2/.libs -lgmp
LIBS2 = lib/relic/relic-target/lib/librelic_s.a \
        lib/libsodium-1.0.16/src/libsodium/.libs/libsodium.a \
		lib/gmp-6.1.2/.libs/libgmp.a

CPP = g++
CPPFLAGS ?= $(INC_FLAGS) -std=c++11 -Wall -pedantic -g

.PHONY: all
all: $(TMPFILE)

$(TMPFILE): $(OBJS_BIN)
	ar rsv $@ $^
	ranlib $@
	libtool -static -o $(OUTPUTFILE) $(TMPFILE) $(LIBS2)
	rm -f $(TMPFILE)

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
	rm -rf $(TARGET_TEST) $(TARGET_BENCH) $(OBJS_TEST) $(OBJS_BENCH) $(TMPFILE) $(OUTPUTFILE)
