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

# Use pipes and not temp files.
CFLAGS += -pipe
# optimize even more
CFLAGS += -O2
# let the type char be unsigned by default
CFLAGS += -funsigned-char
CFLAGS += -fstrict-aliasing
# turn on all common warnings
CFLAGS += -Wall
# turn on extra warnings
CFLAGS += $(if $(GCC4),-Wextra,-W)
# treat warnings as errors
CFLAGS += -Werror
CFLAGS += -Wchar-subscripts
# warn about undefined preprocessor identifiers
CFLAGS += -Wundef
# warn about local variable shadowing another local variable
#CFLAGS += -Wshadow
# warn about casting of pointers to increased alignment requirements
CFLAGS += -Wcast-align
# make string constants const
CFLAGS += -Wwrite-strings
# warn about implicit conversions with side effects
# fgets, calloc and friends take an int, not size_t...
#CFLAGS += -Wconversion
# warn about comparisons between signed and unsigned values
CFLAGS += -Wsign-compare
# warn about unused declared stuff
CFLAGS += -Wunused
CFLAGS += -Wno-unused-parameter
# warn about variable use before initialization
CFLAGS += -Wuninitialized
# warn about variables which are initialized with themselves
CFLAGS += $(if $(GCC4),-Winit-self)
# warn about pointer arithmetic on void* and function pointers
CFLAGS += -Wpointer-arith
# warn about multiple declarations
#CFLAGS += -Wredundant-decls
# warn if the format string is not a string literal
CFLAGS += -Wformat-nonliteral
# do not warn about zero-length formats.
CFLAGS += -Wno-format-zero-length
# do not warn about strftime format with y2k issues
CFLAGS += -Wno-format-y2k
# warn about functions without format attribute that should have one
CFLAGS += -Wmissing-format-attribute
