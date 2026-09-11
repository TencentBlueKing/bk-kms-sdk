# shared build rules for bk-kms-sdk C++.

CUR_WORK_DIR ?= $(notdir $(shell pwd))
TMPPATH       = ${BUILD_TEMP_DIR}/${CUR_WORK_DIR}

INCLUDEF += -I${MODULE_ROOT}/include
INCLUDEF += -I${MODULE_ROOT}/source
INCLUDEF += -I/usr/local/include
INCLUDEF += -I/usr/include

PROGRAMSET += -std=c++11
PROGRAMSET += -g -O2
PROGRAMSET += -Wno-deprecated-declarations
PROGRAMSET += -DRAPIDJSON_HAS_STDSTRING=1

ifndef ENABLE_ASSERT
PROGRAMSET += -DNDEBUG
endif

MKDIR   = mkdir -p
ECHO    = $(if $(filter Linux,$(shell uname)),echo -e,echo)
CP      = cp
RM      = rm
AR      = ar
CXX     = g++
CC      = gcc
SRCEXTS = .cpp .c

SOURCES = $(foreach d,$(SRC_DIR),$(wildcard $(addprefix $(d)*,$(SRCEXTS))))
OBJS   := $(foreach x,${SRCEXTS},$(subst ${CURDIR},${TMPPATH},$(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES)))))

$(TMPPATH)%.o : ${CURDIR}%.cpp
	@$(MKDIR) $(dir $@)
	@$(ECHO) "> $(CXX) -c $(PROGRAMSET) $<"
	@$(CXX) -c $(INCLUDEF) $(PROGRAMSET) $< -o $@

$(TMPPATH)%.o : ${CURDIR}%.c
	@$(MKDIR) $(dir $@)
	@$(ECHO) "> $(CC) -c $(PROGRAMSET) $<"
	@$(CC) -c $(INCLUDEF) $(PROGRAMSET) $< -o $@

ifdef STATICPROCNAME
STATICPROGRAM       = ${TMPPATH}/${STATICPROCNAME}
STATICPROGRAM_INST  = ${BUILD_LIBS_DIR}/${STATICPROCNAME}

.PHONY: static clean

static: $(STATICPROGRAM_INST)

$(STATICPROGRAM_INST): $(STATICPROGRAM)
	@$(MKDIR) ${BUILD_LIBS_DIR}
	@$(CP) -rf $(STATICPROGRAM) $(STATICPROGRAM_INST)

$(STATICPROGRAM): $(OBJS)
	@$(ECHO) "\033[32m\nLinking $(STATICPROCNAME) ...\033[0m"
	@$(AR) -r $(STATICPROGRAM) $(OBJS)

clean:
	@$(RM) -rf ${TMPPATH} $(STATICPROGRAM_INST)
endif

ifdef TARGET
BIN = ${BUILD_BIN_DIR}/${TARGET}

.PHONY: binary clean

binary: $(BIN)

$(BIN): $(OBJS)
	@$(MKDIR) ${BUILD_BIN_DIR}
	@$(ECHO) "\033[32m\nLinking $(TARGET) ...\033[0m"
	$(CXX) -o $(BIN) $(OBJS) $(LIBRARYFILES)

clean:
	@$(RM) -rf ${TMPPATH} $(BIN)
endif
