######################################################################
#
# Copyright (c) 2026 Hideaki Narita
#
######################################################################

PROJNAME=mycrypto
TARGETEXE=$(PROJNAME)

PROJECTROOT=../

SRCROOT=$(PROJECTROOT)src/main/cpp/

BINROOT=$(PROJECTROOT)bin/
BINDIR=$(BINROOT)$(PLATFORM)/$(CONFIGURATION)/
OBJROOT=obj/
OBJDIR=$(OBJROOT)$(PLATFORM)/$(CONFIGURATION)/

PLATFORM=linux
CONFIGURATION=Debug

DESTDIR=/usr/local/
DESTBINDIR=$(DESTDIR)bin/

######################################################################

COMPILE=$(CC) $(CFLAGS) $(CPPFLAGS) -c
LINK=$(LD) $(LDFLAGS)

CC=g++
CFLAGS=$(STDCFLAGS) $(USRCFLAGS) $(EXTCFLAGS)
CPPFLAGS=$(STDCPPFLAGS) $(USRCPPFLAGS) $(EXTCPPFLAGS)
LD=g++
LDFLAGS=$(STDLDFLAGS) $(USRLDFLAGS) $(EXTLDFLAGS)

STDCFLAGS=-Wall -Werror
STDCPPFLAGS=-I $(SRCROOT) -I $(SRCROOT)linux/ -I /opt/openssl/include -DLINUX 
STDLDFLAGS=-L /opt/openssl/lib64
STDLIBS=-lcrypto -lssl

ifeq ($(CONFIGURATION), release)
USRCFLAGS=-O3
USRCPPFLAGS=
else
USRCFLAGS=-g
USRCPPFLAGS=-D_DEBUG
endif
USRLDFLAGS=

######################################################################

RM=rm -f
RMALL=rm -fr
MKDIR=mkdir
MKDIRS=mkdir -p
INSTALL=install

######################################################################

$(OBJDIR)%.o: $(SRCROOT)%.cpp
	@test -d $(@D) || $(MKDIRS) $(@D)
	$(COMPILE) -o $@ $<

$(OBJDIR)linux/%.o: $(SRCROOT)linux/%.cpp
	@test -d $(@D) || $(MKDIRS) $(@D)
	$(COMPILE) -o $@ $<

######################################################################

all::

clean distclean::
	$(RM) *~

clean::
	$(RMALL) $(BINDIR)

clean::
	$(RMALL) $(OBJDIR)

distclean::
	$(RMALL) $(BINROOT)

distclean::
	$(RMALL) $(OBJROOT)

both:: Release Debug

Release Debug::
	$(MAKE) all CONFIGURATION=$@

release-clean::
	$(MAKE) clean CONFIGURATION=Release

debug-clean::
	$(MAKE) clean CONFIGURATION=Debug

######################################################################

PROJ1=$(BINDIR)$(TARGETEXE)
OBJS1=$(OBJDIR)ByteString.o \
	$(OBJDIR)Cipher.o \
	$(OBJDIR)CipherPtr.o \
	$(OBJDIR)CommandLine.o \
	$(OBJDIR)CommandLineParameters.o \
	$(OBJDIR)Digest.o \
	$(OBJDIR)DigestMode.o \
	$(OBJDIR)DigestPtr.o \
	$(OBJDIR)Heap.o \
	$(OBJDIR)Main.o \
	$(OBJDIR)MyCryptographyUtilityApplication.o \
	$(OBJDIR)Parameter.o \
	$(OBJDIR)StringEx.o \
	$(OBJDIR)linux/CipherPlatform.o \
	$(OBJDIR)linux/DigestPlatform.o \
	$(OBJDIR)linux/Decrypter.o \
	$(OBJDIR)linux/DecrypterCBC.o \
	$(OBJDIR)linux/DecrypterCCM.o \
	$(OBJDIR)linux/DecrypterCFB1.o \
	$(OBJDIR)linux/DecrypterCFB8.o \
	$(OBJDIR)linux/DecrypterCFB128.o \
	$(OBJDIR)linux/DecrypterECB.o \
	$(OBJDIR)linux/DecrypterGCM.o \
	$(OBJDIR)linux/Encrypter.o \
	$(OBJDIR)linux/EncrypterCBC.o \
	$(OBJDIR)linux/EncrypterCCM.o \
	$(OBJDIR)linux/EncrypterCFB1.o \
	$(OBJDIR)linux/EncrypterCFB8.o \
	$(OBJDIR)linux/EncrypterCFB128.o \
	$(OBJDIR)linux/EncrypterECB.o \
	$(OBJDIR)linux/EncrypterGCM.o \
	$(OBJDIR)linux/File.o
	
LIBS1=

$(PROJ1): $(OBJS1)
	@test -d $(BINDIR) || $(MKDIRS) $(BINDIR)
	$(LINK) -o $@ $(OBJS1) $(LIBS1) $(STDLIBS)

all:: $(PROJ1)

install::
	$(MAKE) bin-install CONFIGURATION=Release

bin-install:: $(PROJ1)
	$(INSTALL) -m 755 $(PROJ1) $(DESTBINDIR)$(TARGETEXE)
