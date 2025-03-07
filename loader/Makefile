CC = clang
CFLAGS = -g -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lusb-1.0

ifeq ($(XNUSPY_SERIAL), 1)
	CFLAGS += -DXNUSPY_SERIAL
endif

TARGET = loader

SOURCES = loader.c

$(TARGET) : $(SOURCES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SOURCES) -o $(TARGET)
