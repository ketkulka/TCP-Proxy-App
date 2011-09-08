UTCP_SRC=./source
LIBS= $(UTCP_SRC)/libs
LIB_LIST= $(LIBS)/list
LIB_TIMER= $(LIBS)/timer
UTCP_LIB_FILE= utcp
UTCP_OBJ_DIR= ./obj
UTCP_LIB_DIR= ./obj
BIN= ./bin



CP = cp
RM = rm -f
MV = mv

CC        = gcc
OPT       = 
DEBUG     =  -g
DEFINES   =
INCLUDE   = -I.
CFLAGS    = $(DEBUG) $(OPT) $(DEFINES) $(INCLUDE)
LIBS      = -l$(UTCP_LIB_FILE)
AR        = ar
ARFLAGS   = -cru

all: 
	@ $(CC) $(CFLAGS) test_app.c -o proxy_app.out $(LIBS)

clean:
	@ $(RM) proxy_app.out
