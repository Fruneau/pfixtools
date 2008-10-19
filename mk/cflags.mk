##############################################################################
#          pfixtools: a collection of postfix related tools                  #
#          ~~~~~~~~~                                                         #
#  ________________________________________________________________________  #
#                                                                            #
#  Redistribution and use in source and binary forms, with or without        #
#  modification, are permitted provided that the following conditions        #
#  are met:                                                                  #
#                                                                            #
#  1. Redistributions of source code must retain the above copyright         #
#     notice, this list of conditions and the following disclaimer.          #
#  2. Redistributions in binary form must reproduce the above copyright      #
#     notice, this list of conditions and the following disclaimer in the    #
#     documentation and/or other materials provided with the distribution.   #
#  3. The names of its contributors may not be used to endorse or promote    #
#     products derived from this software without specific prior written     #
#     permission.                                                            #
#                                                                            #
#  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND   #
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE     #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR        #
#  PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS    #
#  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR    #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF      #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS  #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN   #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)   #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF    #
#  THE POSSIBILITY OF SUCH DAMAGE.                                           #
##############################################################################

ifneq ($(filter 4.%,$(shell gcc -dumpversion)),)
  GCC4=1
endif
ifneq ($(filter Darwin%,$(shell uname)),)
  DARWIN=1
endif

# Use pipes and not temp files.
CFLAGSBASE += -pipe
# optimize even more
CFLAGSBASE += -O2
# let the type char be unsigned by default
CFLAGSBASE += -funsigned-char
CFLAGSBASE += -fno-strict-aliasing
# turn on all common warnings
CFLAGSBASE += -Wall
# turn on extra warnings
CFLAGSBASE += $(if $(GCC4),-Wextra,-W)
# treat warnings as errors
CFLAGSBASE += -Werror
CFLAGSBASE += -Wchar-subscripts
# warn about undefined preprocessor identifiers
CFLAGSBASE += -Wundef
# warn about local variable shadowing another local variable
# # disabled on Darwin because of warnings in ev.h
CFLAGSBASE += -Wshadow
# warn about casting of pointers to increased alignment requirements
CFLAGSBASE += -Wcast-align
# make string constants const
CFLAGSBASE += -Wwrite-strings
# warn about implicit conversions with side effects
# fgets, calloc and friends take an int, not size_t...
#CFLAGSBASE += -Wconversion
# warn about comparisons between signed and unsigned values
CFLAGSBASE += -Wsign-compare
# warn about unused declared stuff
CFLAGSBASE += -Wunused
CFLAGSBASE += -Wno-unused-parameter
# warn about variable use before initialization
CFLAGSBASE += -Wuninitialized
# warn about variables which are initialized with themselves
CFLAGSBASE += $(if $(GCC4),-Winit-self)
# warn about pointer arithmetic on void* and function pointers
CFLAGSBASE += -Wpointer-arith
# warn about multiple declarations
# #disabled on Darwin because of warnings in ev.h
CFLAGSBASE += -Wredundant-decls
# warn if the format string is not a string literal
CFLAGSBASE += -Wformat-nonliteral
# do not warn about zero-length formats.
CFLAGSBASE += -Wno-format-zero-length
# do not warn about strftime format with y2k issues
CFLAGSBASE += -Wno-format-y2k
# warn about functions without format attribute that should have one
CFLAGSBASE += -Wmissing-format-attribute

CFLAGS=$(CFLAGSBASE)
LDFLAGS=$(LDFLAGSBASE)
