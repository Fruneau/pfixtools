##############################################################################
#          postlicyd: a postfix policy daemon with a lot of features         #
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

DC:=gdc

ifneq ($(filter 4.%,$(shell gcc -dumpversion)),)
  GCC4=1
endif

# Use pipes and not temp files.
DFLAGS += -pipe
# optimize even more
DFLAGS += -O2
# let the type char be unsigned by default
DFLAGS += -funsigned-char
DFLAGS += -fstrict-aliasing
# turn on all common warnings
DFLAGS += -Wall
# turn on extra warnings
DFLAGS += $(if $(GCC4),-Wextra,-W)
# treat warnings as errors
DFLAGS += -Werror
DFLAGS += -Wchar-subscripts
# warn about undefined preprocessor identifiers
DFLAGS += -Wundef
# warn about local variable shadowing another local variable
DFLAGS += -Wshadow
# warn about casting of pointers to increased alignment requirements
DFLAGS += -Wcast-align
# make string constants const
DFLAGS += -Wwrite-strings
# warn about implicit conversions with side effects
# fgets, calloc and friends take an int, not size_t...
#DFLAGS += -Wconversion
# warn about comparisons between signed and unsigned values
DFLAGS += -Wsign-compare
# warn about unused declared stuff
DFLAGS += -Wunused
DFLAGS += -Wno-unused-parameter
# warn about variable use before initialization
DFLAGS += -Wuninitialized
# warn about variables which are initialized with themselves
DFLAGS += -Winit-self
# warn about pointer arithmetic on void* and function pointers
DFLAGS += -Wpointer-arith
# warn about multiple declarations
DFLAGS += -Wredundant-decls
# warn if the format string is not a string literal
DFLAGS += -Wformat-nonliteral
# do not warn about zero-length formats.
DFLAGS += -Wno-format-zero-length
# missing prototypes
DFLAGS += -Wmissing-prototypes
# warn about functions without format attribute that should have one
DFLAGS += -Wmissing-format-attribute
# barf if we change constness
#DFLAGS += -Wcast-qual

