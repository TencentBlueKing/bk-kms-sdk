export MODULE_ROOT     = $(CURDIR)
export BUILD_DIR       = $(MODULE_ROOT)/build
export BUILD_TEMP_DIR  = $(BUILD_DIR)/tmp
export BUILD_LIBS_DIR  = $(BUILD_DIR)/lib

ECHO = $(if $(filter Linux,$(shell uname)),echo -e,echo)

.PHONY: default lib deps install clean

default: lib

lib:
	@$(ECHO) "\033[32m\nBuilding libbkkms.a ...\033[0m"
	@+make static -C source

deps:
	@$(ECHO) "\033[32m\nInstalling third-party dependences ...\033[0m"
	@cd third-party && sh install.sh
	@$(ECHO) "\033[32m\nInstalled third-party dependences successfully\033[0m"

install: lib
	@install -d /usr/local/include/bk-kms
	@cp -rf include/bk-kms/* /usr/local/include/bk-kms/
	@install -d /usr/local/lib
	@install -m 0644 $(BUILD_LIBS_DIR)/libbkkms.a /usr/local/lib/
	@$(ECHO) "\033[32m\nInstalled bk-kms-sdk successfully\033[0m"

clean:
	@rm -rf build
	@make clean -s -C source
