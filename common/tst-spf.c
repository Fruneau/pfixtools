/******************************************************************************/
/*          pfixtools: a collection of postfix related tools                  */
/*          ~~~~~~~~~                                                         */
/*  ________________________________________________________________________  */
/*                                                                            */
/*  Redistribution and use in source and binary forms, with or without        */
/*  modification, are permitted provided that the following conditions        */
/*  are met:                                                                  */
/*                                                                            */
/*  1. Redistributions of source code must retain the above copyright         */
/*     notice, this list of conditions and the following disclaimer.          */
/*  2. Redistributions in binary form must reproduce the above copyright      */
/*     notice, this list of conditions and the following disclaimer in the    */
/*     documentation and/or other materials provided with the distribution.   */
/*  3. The names of its contributors may not be used to endorse or promote    */
/*     products derived from this software without specific prior written     */
/*     permission.                                                            */
/*                                                                            */
/*  THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND ANY EXPRESS   */
/*  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED         */
/*  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE    */
/*  DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE FOR ANY         */
/*  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL        */
/*  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS   */
/*  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)     */
/*  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,       */
/*  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN  */
/*  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE           */
/*  POSSIBILITY OF SUCH DAMAGE.                                               */
/*                                                                            */
/*   Copyright (c) 2006-2009 the Authors                                      */
/*   see AUTHORS and source files for details                                 */
/******************************************************************************/

/*
 * Copyright © 2009 Florent Bruneau
 */

/* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! *
 *  To run the test, you must have a resolv.conf in your current directoy with *
 *  the following content:                                                     *
 *                                                                             *
 *  search example.com                                                         *
 *  nameserver 88.163.156.52                                                   *
 *                                                                             *
 *  The IP of the nameserver may change in the future.                         *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! */

#include "spf.h"
#include "server.h"

typedef struct spf_test_t {
    const char* testid;
    const char* scenario;
    const char* spec;
    const char* helo;
    const char* ip;
    const char* sender;
    int result1;
    int result2;
} spf_test_t;

/* Test cases imported from openspf.org testsuite rfc4408-tests-2008.08.yml
 * Contributors:
 *   Stuart D Gathman    90% of the tests
 *   Julian Mehnle       some tests, proofread YAML syntax, formal schema
 *   Frank Ellermann
 *   Scott Kitterman
 *   Wayne Schlitt
 *   Craig Whitmore
 *   Norman Maurer
 *   Mark Shewmaker
 *   Philip Gladstone
 */
static spf_test_t testcases[] = {
    { "helo-not-fqdn", "Initial processing", "4.3/1", "A2345678", "1.2.3.5", "", SPF_NONE, -1 },
    { "emptylabel", "Initial processing", "4.3/1", "mail.test.t0.example.net", "1.2.3.5", "lyme.eater@A...test.t0.example.com", SPF_NONE, -1 },
    { "toolonglabel", "Initial processing", "4.3/1", "mail.test.t0.example.net", "1.2.3.5", "lyme.eater@A123456789012345678901234567890123456789012345678901234567890123.test.t0.example.com", SPF_NONE, -1 },
    { "longlabel", "Initial processing", "4.3/1", "mail.test.t0.example.net", "1.2.3.5", "lyme.eater@A12345678901234567890123456789012345678901234567890123456789012.test.t0.example.com", SPF_FAIL, -1 },
    { "nolocalpart", "Initial processing", "4.3/2", "mail.test.t0.example.net", "1.2.3.4", "@test.t0.example.net", SPF_FAIL, -1 },
    { "domain-literal", "Initial processing", "4.3/1", "OEMCOMPUTER", "1.2.3.5", "foo@[1.2.3.5]", SPF_NONE, -1 },
    { "helo-domain-literal", "Initial processing", "4.3/1", "[1.2.3.5]", "1.2.3.5", "", SPF_NONE, -1 },
    /* Not applicable, cannot simulate DNS timeout { "alltimeout", "Record lookup", "4.4/2", "mail.test.t1.example.net", "1.2.3.4", "foo@alltimeout.test.t1.example.net", SPF_TEMPERROR, -1 }, */
    { "both", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@both.test.t1.example.net", SPF_FAIL, -1 },
    { "txttimeout", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@txttimeout.test.t1.example.net", SPF_FAIL, SPF_TEMPERROR },
    { "spfonly", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@spfonly.test.t1.example.net", SPF_FAIL, SPF_NONE },
    { "txtonly", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@txtonly.test.t1.example.net", SPF_FAIL, SPF_NONE },
    { "spftimeout", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@spftimeout.test.t1.example.net", SPF_FAIL, SPF_TEMPERROR },
    { "nospftxttimeout", "Record lookup", "4.4/1", "mail.test.t1.example.net", "1.2.3.4", "foo@nospftxttimeout.test.t1.example.net", SPF_TEMPERROR, SPF_NONE },
    { "nospace2", "Selecting records", "4.5/4", "mail.test1.t2.example.com", "1.2.3.4", "foo@test3.t2.example.com", SPF_PASS, -1 },
    { "nospace1", "Selecting records", "4.5/4", "mail.test1.t2.example.com", "1.2.3.4", "foo@test2.t2.example.com", SPF_NONE, -1 },
    { "spfoverride", "Selecting records", "4.5/5", "mail.test1.t2.example.com", "1.2.3.4", "foo@test4.t2.example.com", SPF_PASS, SPF_FAIL },
    { "nospf", "Selecting records", "4.5/7", "mail.test1.t2.example.com", "1.2.3.4", "foo@mail.test1.t2.example.com", SPF_NONE, -1 },
    { "case-insensitive", "Selecting records", "4.5/6", "mail.test1.t2.example.com", "1.2.3.4", "foo@test9.t2.example.com", SPF_SOFTFAIL, -1 },
    { "multitxt2", "Selecting records", "4.5/6", "mail.test1.t2.example.com", "1.2.3.4", "foo@test6.t2.example.com", SPF_PERMERROR, -1 },
    { "multitxt1", "Selecting records", "4.5/5", "mail.test1.t2.example.com", "1.2.3.4", "foo@test5.t2.example.com", SPF_PASS, SPF_PERMERROR },
    { "multispf1", "Selecting records", "4.5/6", "mail.test1.t2.example.com", "1.2.3.4", "foo@test7.t2.example.com", SPF_PERMERROR, SPF_FAIL },
    { "multispf2", "Selecting records", "4.5/6", "mail.test1.t2.example.com", "1.2.3.4", "foo@test8.t2.example.com", SPF_PERMERROR, SPF_PASS },
    { "empty", "Selecting records", "4.5/4", "mail1.test1.t2.example.com", "1.2.3.4", "foo@test1.t2.example.com", SPF_NEUTRAL, -1 },
    { "modifier-charset-bad2", "Record evaluation", "4.6.1/4", "mail.test.t3.example.com", "1.2.3.4", "foo@t4.test.t3.example.com", SPF_PERMERROR, -1 },
    { "modifier-charset-bad1", "Record evaluation", "4.6.1/4", "mail.test.t3.example.com", "1.2.3.4", "foo@t3.test.t3.example.com", SPF_PERMERROR, -1 },
    { "redirect-after-mechanisms2", "Record evaluation", "4.6.3", "mail.test.t3.example.com", "1.2.3.5", "foo@t6.test.t3.example.com", SPF_FAIL, -1 },
    { "detect-errors-anywhere", "Record evaluation", "4.6", "mail.test.t3.example.com", "1.2.3.4", "foo@t1.test.t3.example.com", SPF_PERMERROR, -1 },
    { "redirect-after-mechanisms1", "Record evaluation", "4.6.3", "mail.test.t3.example.com", "1.2.3.4", "foo@t5.test.t3.example.com", SPF_SOFTFAIL, -1 },
    { "invalid-domain", "Record evaluation", "8.1/2", "mail.test.t3.example.com", "1.2.3.4", "foo@t9.test.t3.example.com", SPF_PERMERROR, -1 },
    { "modifier-charset-good", "Record evaluation", "4.6.1/2", "mail.test.t3.example.com", "1.2.3.4", "foo@t2.test.t3.example.com", SPF_PASS, -1 },
    { "invalid-domain-empty-label", "Record evaluation", "['4.3/1', '5/10/3']", "mail.test.t3.example.com", "1.2.3.4", "foo@t10.test.t3.example.com", SPF_PERMERROR, SPF_FAIL },
    { "invalid-domain-long", "Record evaluation", "['4.3/1', '5/10/3']", "mail.test.t3.example.com", "1.2.3.4", "foo@t11.test.t3.example.com", SPF_PERMERROR, SPF_FAIL },
    { "invalid-domain-long-via-macro", "Record evaluation", "['4.3/1', '5/10/3']", "%%%%%%%%%%%%%%%%%%%%%%", "1.2.3.4", "foo@t12.test.t3.example.com", SPF_PERMERROR, SPF_FAIL },
    { "redirect-is-modifier", "Record evaluation", "4.6.1/4", "mail.test.t3.example.com", "1.2.3.4", "foo@t8.test.t3.example.com", SPF_PERMERROR, -1 },
    { "default-result", "Record evaluation", "4.7/1", "mail.test.t3.example.com", "1.2.3.5", "foo@t7.test.t3.example.com", SPF_NEUTRAL, -1 },
    { "all-arg", "ALL mechanism syntax", "5.1/1", "mail.test.t4.example.com", "1.2.3.4", "foo@e2.test.t4.example.com", SPF_PERMERROR, -1 },
    { "all-cidr", "ALL mechanism syntax", "5.1/1", "mail.test.t4.example.com", "1.2.3.4", "foo@e3.test.t4.example.com", SPF_PERMERROR, -1 },
    { "all-dot", "ALL mechanism syntax", "5.1/1", "mail.test.t4.example.com", "1.2.3.4", "foo@e1.test.t4.example.com", SPF_PERMERROR, -1 },
    { "all-neutral", "ALL mechanism syntax", "5.1/1", "mail.test.t4.example.com", "1.2.3.4", "foo@e4.test.t4.example.com", SPF_NEUTRAL, -1 },
    { "all-double", "ALL mechanism syntax", "5.1/1", "mail.test.t4.example.com", "1.2.3.4", "foo@e5.test.t4.example.com", SPF_PASS, -1 },
    { "ptr-cidr", "PTR mechanism syntax", "5.5/2", "mail.test.t5.example.com", "1.2.3.4", "foo@e1.test.t5.example.com", SPF_PERMERROR, -1 },
    { "ptr-match-implicit", "PTR mechanism syntax", "5.5/5", "mail.test.t5.example.com", "1.2.3.4", "foo@e3.test.t5.example.com", SPF_PASS, -1 },
    { "ptr-nomatch-invalid", "PTR mechanism syntax", "5.5/5", "mail.test.t5.example.com", "1.2.3.4", "foo@e4.test.t5.example.com", SPF_FAIL, -1 },
    { "ptr-match-ip6", "PTR mechanism syntax", "5.5/5", "mail.test.t5.example.com", "CAFE:BABE::1", "foo@e3.test.t5.example.com", SPF_PASS, -1 },
    { "ptr-empty-domain", "PTR mechanism syntax", "5.5/2", "mail.test.t5.example.com", "1.2.3.4", "foo@e5.test.t5.example.com", SPF_PERMERROR, -1 },
    { "ptr-match-target", "PTR mechanism syntax", "5.5/5", "mail.test.t5.example.com", "1.2.3.4", "foo@e2.test.t5.example.com", SPF_PASS, -1 },
    { "a-bad-domain", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e9.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-only-toplabel-trailing-dot", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e5b.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-cidr4-0", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1.2.3.4", "foo@e2.test.t6.example.com", SPF_PASS, -1 },
    { "a-cidr6-0-ip4", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1.2.3.4", "foo@e2a.test.t6.example.com", SPF_FAIL, -1 },
    { "a-cidr6-0-nxdomain", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1234::1", "foo@e2b.test.t6.example.com", SPF_FAIL, -1 },
    { "a-numeric-toplabel", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e5.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-bad-cidr4", "A mechanism syntax", "5.3/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e6a.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-bad-cidr6", "A mechanism syntax", "5.3/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e7.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-numeric", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e4.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-dash-in-toplabel", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e14.test.t6.example.com", SPF_PASS, -1 },
    { "a-colon-domain-ip4mapped", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "::FFFF:1.2.3.4", "foo@e11.test.t6.example.com", SPF_PASS, SPF_NEUTRAL },
    { "a-cidr6-0-ip4mapped", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "::FFFF:1.2.3.4", "foo@e2a.test.t6.example.com", SPF_FAIL, -1 },
    { "a-only-toplabel", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e5a.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-empty-domain", "A mechanism syntax", "5.3/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e13.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-colon-domain", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e11.test.t6.example.com", SPF_PASS, SPF_NEUTRAL },
    { "a-cidr6-0-ip6", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1234::1", "foo@e2a.test.t6.example.com", SPF_PASS, -1 },
    { "a-multi-ip1", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1.2.3.4", "foo@e10.test.t6.example.com", SPF_PASS, -1 },
    { "a-multi-ip2", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1.2.3.4", "foo@e10.test.t6.example.com", SPF_PASS, -1 },
    { "a-bad-toplabel", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e12.test.t6.example.com", SPF_PERMERROR, -1 },
    { "a-cidr6", "A mechanism syntax", "5.3/2", "mail.test.t6.example.com", "1.2.3.4", "foo@e6.test.t6.example.com", SPF_FAIL, -1 },
    { "a-cidr4-0-ip6", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1234::1", "foo@e2.test.t6.example.com", SPF_FAIL, -1 },
    { "a-nxdomain", "A mechanism syntax", "5.3/3", "mail.test.t6.example.com", "1.2.3.4", "foo@e1.test.t6.example.com", SPF_FAIL, -1 },
    { "a-null", "A mechanism syntax", "8.1/2", "mail.test.t6.example.com", "1.2.3.5", "foo@e3.test.t6.example.com", SPF_PERMERROR, -1 },
    { "include-none", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e7.test.t7.example.com", SPF_PERMERROR, -1 },
    { "include-softfail", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e2.test.t7.example.com", SPF_PASS, -1 },
    { "include-syntax-error", "Include mechanism semantics and syntax", "5.2/1", "mail.test.t7.example.com", "1.2.3.4", "foo@e6.test.t7.example.com", SPF_PERMERROR, -1 },
    { "include-fail", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e1.test.t7.example.com", SPF_SOFTFAIL, -1 },
    /* Not applicable, cannot simulate DNS timeout { "include-temperror", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e4.test.t7.example.com", SPF_TEMPERROR, -1 }, */
    { "include-empty-domain", "Include mechanism semantics and syntax", "5.2/1", "mail.test.t7.example.com", "1.2.3.4", "foo@e8.test.t7.example.com", SPF_PERMERROR, -1 },
    { "include-neutral", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e3.test.t7.example.com", SPF_FAIL, -1 },
    { "include-permerror", "Include mechanism semantics and syntax", "5.2/9", "mail.test.t7.example.com", "1.2.3.4", "foo@e5.test.t7.example.com", SPF_PERMERROR, -1 },
    { "include-cidr", "Include mechanism semantics and syntax", "5.2/1", "mail.test.t7.example.com", "1.2.3.4", "foo@e9.test.t7.example.com", SPF_PERMERROR, -1 },
    { "mx-cidr4-0-ip6", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1234::1", "foo@e2.test.t8.example.com", SPF_FAIL, -1 },
    /* Not Applicable, empty MX entry not accepted by bind { "mx-empty", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "", SPF_NEUTRAL, -1 }, */
    { "mx-colon-domain-ip4mapped", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "::FFFF:1.2.3.4", "foo@e11.test.t8.example.com", SPF_PASS, SPF_NEUTRAL },
    { "mx-nxdomain", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "foo@e1.test.t8.example.com", SPF_FAIL, -1 },
    { "mx-numeric-top-label", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e5.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-null", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "1.2.3.5", "foo@e3.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-bad-toplab", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e12.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-cidr6-0-ip4mapped", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "::FFFF:1.2.3.4", "foo@e2a.test.t8.example.com", SPF_FAIL, -1 },
    { "mx-multi-ip2", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "foo@e10.test.t8.example.com", SPF_PASS, -1 },
    { "mx-cidr6-0-ip6", "MX mechanism syntax", "5.3/3", "mail.test.t8.example.com", "1234::1", "foo@e2a.test.t8.example.com", SPF_PASS, -1 },
    { "mx-implicit", "MX mechanism syntax", "5.4/4", "mail.test.t8.example.com", "1.2.3.4", "foo@e4.test.t8.example.com", SPF_NEUTRAL, -1 },
    { "mx-cidr6-0-ip4", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "foo@e2a.test.t8.example.com", SPF_FAIL, -1 },
    { "mx-cidr6-0-nxdomain", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1234::1", "foo@e2b.test.t8.example.com", SPF_FAIL, -1 },
    { "mx-cidr6", "MX mechanism syntax", "5.4/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e6.test.t8.example.com", SPF_FAIL, -1 },
    { "mx-multi-ip1", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "foo@e10.test.t8.example.com", SPF_PASS, -1 },
    { "mx-bad-cidr6", "MX mechanism syntax", "5.4/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e7.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-bad-domain", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e9.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-colon-domain", "MX mechanism syntax", "8.1/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e11.test.t8.example.com", SPF_PASS, SPF_NEUTRAL },
    { "mx-bad-cidr4", "MX mechanism syntax", "5.4/2", "mail.test.t8.example.com", "1.2.3.4", "foo@e6a.test.t8.example.com", SPF_PERMERROR, -1 },
    { "mx-cidr4-0", "MX mechanism syntax", "5.4/3", "mail.test.t8.example.com", "1.2.3.4", "foo@e2.test.t8.example.com", SPF_PASS, -1 },
    { "mx-empty-domain", "MX mechanism syntax", "5.2/1", "mail.test.t8.example.com", "1.2.3.4", "foo@e13.test.t8.example.com", SPF_PERMERROR, -1 },
    { "exists-cidr", "EXISTS mechanism syntax", "5.7/2", "mail.test.t9.example.com", "1.2.3.4", "foo@e3.test.t9.example.com", SPF_PERMERROR, -1 },
    { "exists-implicit", "EXISTS mechanism syntax", "5.7/2", "mail.test.t9.example.com", "1.2.3.4", "foo@e2.test.t9.example.com", SPF_PERMERROR, -1 },
    { "exists-empty-domain", "EXISTS mechanism syntax", "5.7/2", "mail.test.t9.example.com", "1.2.3.4", "foo@e1.test.t9.example.com", SPF_PERMERROR, -1 },
    { "cidr4-0", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e1.test.t10.example.com", SPF_PASS, -1 },
    { "cidr4-32", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e2.test.t10.example.com", SPF_PASS, -1 },
    { "cidr4-33", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e3.test.t10.example.com", SPF_PERMERROR, -1 },
    { "bad-ip4-short", "IP4 mechanism syntax", "5.6/4", "mail.test.t10.example.com", "1.2.3.4", "foo@e9.test.t10.example.com", SPF_PERMERROR, -1 },
    { "bare-ip4", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e5.test.t10.example.com", SPF_PERMERROR, -1 },
    { "cidr4-032", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e4.test.t10.example.com", SPF_PERMERROR, -1 },
    { "ip4-dual-cidr", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e6.test.t10.example.com", SPF_PERMERROR, -1 },
    { "bad-ip4-port", "IP4 mechanism syntax", "5.6/2", "mail.test.t10.example.com", "1.2.3.4", "foo@e8.test.t10.example.com", SPF_PERMERROR, -1 },
    { "ip4-mapped-ip6", "IP4 mechanism syntax", "5/9/2", "mail.test.t10.example.com", "::FFFF:1.2.3.4", "foo@e7.test.t10.example.com", SPF_FAIL, -1 },
    { "bare-ip6", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e1.test.t11.example.com", SPF_PERMERROR, -1 },
    { "ip6-bad1", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e6.test.t11.example.com", SPF_PERMERROR, -1 },
    { "cidr6-33", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "CAFE:BABE:8000::", "foo@e5.test.t11.example.com", SPF_PASS, -1 },
    { "cidr6-0", "IP6 mechanism syntax", "5/8", "mail.test.t11.example.com", "DEAF:BABE::CAB:FEE", "foo@e2.test.t11.example.com", SPF_PASS, -1 },
    { "cidr6-ip4", "IP6 mechanism syntax", "5/9/2", "mail.test.t11.example.com", "::FFFF:1.2.3.4", "foo@e2.test.t11.example.com", SPF_NEUTRAL, SPF_PASS },
    { "cidr6-bad", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e4.test.t11.example.com", SPF_PERMERROR, -1 },
    { "cidr6-129", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e3.test.t11.example.com", SPF_PERMERROR, -1 },
    { "cidr6-0-ip4", "IP6 mechanism syntax", "5/9/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e2.test.t11.example.com", SPF_NEUTRAL, SPF_PASS },
    { "cidr6-33-ip4", "IP6 mechanism syntax", "5.6/2", "mail.test.t11.example.com", "1.2.3.4", "foo@e5.test.t11.example.com", SPF_NEUTRAL, -1 },
    { "default-modifier-obsolete", "Semantics of exp and other modifiers", "6/3", "mail.test.t12.example.com", "1.2.3.4", "foo@e19.test.t12.example.com", SPF_NEUTRAL, -1 },
    { "redirect-cancels-exp", "Semantics of exp and other modifiers", "6.2/13", "mail.test.t12.example.com", "1.2.3.4", "foo@e1.test.t12.example.com", SPF_FAIL, -1 },
    { "default-modifier-obsolete2", "Semantics of exp and other modifiers", "6/3", "mail.test.t12.example.com", "1.2.3.4", "foo@e20.test.t12.example.com", SPF_NEUTRAL, -1 },
    { "explanation-syntax-error", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e13.test.t12.example.com", SPF_FAIL, -1 },
    { "exp-syntax-error", "Semantics of exp and other modifiers", "6.2/1", "mail.test.t12.example.com", "1.2.3.4", "foo@e16.test.t12.example.com", SPF_PERMERROR, -1 },
    { "redirect-none", "Semantics of exp and other modifiers", "6.1/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e10.test.t12.example.com", SPF_PERMERROR, -1 },
    { "exp-twice", "Semantics of exp and other modifiers", "6/2", "mail.test.t12.example.com", "1.2.3.4", "foo@e14.test.t12.example.com", SPF_PERMERROR, -1 },
    { "redirect-empty-domain", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e18.test.t12.example.com", SPF_PERMERROR, -1 },
    { "empty-modifier-name", "Semantics of exp and other modifiers", "A/3", "mail.test.t12.example.com", "1.2.3.4", "foo@e6.test.t12.example.com", SPF_PERMERROR, -1 },
    { "exp-dns-error", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e21.test.t12.example.com", SPF_FAIL, -1 },
    { "redirect-twice", "Semantics of exp and other modifiers", "6/2", "mail.test.t12.example.com", "1.2.3.4", "foo@e15.test.t12.example.com", SPF_PERMERROR, -1 },
    { "exp-multiple-txt", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e11.test.t12.example.com", SPF_FAIL, -1 },
    { "exp-empty-domain", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e12.test.t12.example.com", SPF_PERMERROR, -1 },
    { "unknown-modifier-syntax", "Semantics of exp and other modifiers", "A/3", "mail.test.t12.example.com", "1.2.3.4", "foo@e9.test.t12.example.com", SPF_PERMERROR, -1 },
    { "redirect-syntax-error", "Semantics of exp and other modifiers", "6.1/2", "mail.test.t12.example.com", "1.2.3.4", "foo@e17.test.t12.example.com", SPF_PERMERROR, -1 },
    { "invalid-modifier", "Semantics of exp and other modifiers", "A/3", "mail.test.t12.example.com", "1.2.3.4", "foo@e5.test.t12.example.com", SPF_PERMERROR, -1 },
    { "dorky-sentinel", "Semantics of exp and other modifiers", "8.1/6", "mail.test.t12.example.com", "1.2.3.4", "Macro Error@e8.test.t12.example.com", SPF_FAIL, -1 },
    { "exp-no-txt", "Semantics of exp and other modifiers", "6.2/4", "mail.test.t12.example.com", "1.2.3.4", "foo@e22.test.t12.example.com", SPF_FAIL, -1 },
    { "redirect-cancels-prior-exp", "Semantics of exp and other modifiers", "6.2/13", "mail.test.t12.example.com", "1.2.3.4", "foo@e3.test.t12.example.com", SPF_FAIL, -1 },
    { "include-ignores-exp", "Semantics of exp and other modifiers", "6.2/13", "mail.test.t12.example.com", "1.2.3.4", "foo@e7.test.t12.example.com", SPF_FAIL, -1 },
    { "p-macro-ip4-valid", "Macro expansion rules", "8.1/22", "msgbas2x.cos.test.t13.example.com", "192.168.218.41", "test@e6.test.t13.example.com", SPF_FAIL, -1 },
    { "domain-name-truncation", "Macro expansion rules", "8.1/25", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@somewhat.test.t13.example.com", SPF_FAIL, -1 },
    { "hello-macro", "Macro expansion rules", "8.1/6", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e9.test.t13.example.com", SPF_PASS, -1 },
    { "trailing-dot-exp", "Macro expansion rules", "8.1", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@exp.test.t13.example.com", SPF_FAIL, -1 },
    { "trailing-dot-domain", "Macro expansion rules", "8.1/16", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@test.t13.example.com", SPF_PASS, -1 },
    { "macro-reverse-split-on-dash", "Macro expansion rules", "['8.1/15', '8.1/16', '8.1/17', '8.1/18']", "mail.test.t13.example.com", "1.2.3.4", "philip-gladstone-test@e11.test.t13.example.com", SPF_PASS, -1 },
    { "p-macro-ip6-valid", "Macro expansion rules", "8.1/22", "msgbas2x.cos.test.t13.example.com", "CAFE:BABE::3", "test@e6.test.t13.example.com", SPF_FAIL, -1 },
    { "exp-txt-macro-char", "Macro expansion rules", "8.1/20", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e3.test.t13.example.com", SPF_FAIL, -1 },
    { "invalid-macro-char", "Macro expansion rules", "8.1/9", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e1.test.t13.example.com", SPF_PERMERROR, -1 },
    { "p-macro-ip6-novalid", "Macro expansion rules", "8.1/22", "msgbas2x.cos.test.t13.example.com", "CAFE:BABE::1", "test@e6.test.t13.example.com", SPF_FAIL, -1 },
    { "hello-domain-literal", "Macro expansion rules", "8.1/2", "[192.168.218.40]", "192.168.218.40", "test@e9.test.t13.example.com", SPF_FAIL, -1 },
    { "undef-macro", "Macro expansion rules", "8.1/6", "msgbas2x.cos.test.t13.example.com", "CAFE:BABE::192.168.218.40", "test@e5.test.t13.example.com", SPF_PERMERROR, -1 },
    /* Hey, cannot work, "macro%percent  space%20url-space.test.t13.example.com" is not a valid DNS domain name { "macro-mania-in-domain", "Macro expansion rules", "8.1/3, 8.1/4", "mail.test.t13.example.com", "1.2.3.4", "test@e1a.test.t13.example.com", SPF_PASS, -1 }, */
    { "p-macro-ip4-novalid", "Macro expansion rules", "8.1/22", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e6.test.t13.example.com", SPF_FAIL, -1 },
    { "require-valid-helo", "Macro expansion rules", "8.1/6", "OEMCOMPUTER", "1.2.3.4", "test@e10.test.t13.example.com", SPF_FAIL, -1 },
    { "p-macro-multiple", "Macro expansion rules", "8.1/22", "msgbas2x.cos.test.t13.example.com", "192.168.218.42", "test@e7.test.t13.example.com", SPF_PASS, SPF_SOFTFAIL },
    { "upper-macro", "Macro expansion rules", "8.1/26", "msgbas2x.cos.test.t13.example.com", "192.168.218.42", "jack&jill=up@e8.test.t13.example.com", SPF_FAIL, -1 },
    { "invalid-hello-macro", "Macro expansion rules", "8.1/2", "JUMPIN' JUPITER", "192.168.218.40", "test@e9.test.t13.example.com", SPF_FAIL, -1 },
    { "exp-only-macro-char", "Macro expansion rules", "8.1/8", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e2.test.t13.example.com", SPF_PERMERROR, -1 },
    { "v-macro-ip4", "Macro expansion rules", "8.1/6", "msgbas2x.cos.test.t13.example.com", "192.168.218.40", "test@e4.test.t13.example.com", SPF_FAIL, -1 },
    { "v-macro-ip6", "Macro expansion rules", "8.1/6", "msgbas2x.cos.test.t13.example.com", "CAFE:BABE::1", "test@e4.test.t13.example.com", SPF_FAIL, -1 },
    { "false-a-limit", "Processing limits", "10.1/7", "mail.test.t14.example.com", "1.2.3.12", "foo@e10.test.t14.example.com", SPF_PASS, -1 },
    { "include-at-limit", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e8.test.t14.example.com", SPF_PASS, -1 },
    { "mx-limit", "Processing limits", "10.1/7", "mail.test.t14.example.com", "1.2.3.5", "foo@e4.test.t14.example.com", SPF_NEUTRAL, SPF_PASS },
    { "mech-over-limit", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e7.test.t14.example.com", SPF_PERMERROR, -1 },
    { "include-over-limit", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e9.test.t14.example.com", SPF_PERMERROR, -1 },
    { "redirect-loop", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e1.test.t14.example.com", SPF_PERMERROR, -1 },
    { "mech-at-limit", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e6.test.t14.example.com", SPF_PASS, -1 },
    { "include-loop", "Processing limits", "10.1/6", "mail.test.t14.example.com", "1.2.3.4", "foo@e2.test.t14.example.com", SPF_PERMERROR, -1 },
    { "ptr-limit", "Processing limits", "10.1/7", "mail.test.t14.example.com", "1.2.3.5", "foo@e5.test.t14.example.com", SPF_NEUTRAL, SPF_PASS },
    { NULL, NULL, NULL, NULL, NULL, NULL, -1, -1 }
};
static int tested = 0;
static int passed = 0;

static void spf_test_next(spf_test_t* current);

static void spf_test_done(spf_code_t code, const char* explanation, void* data)
{
    spf_test_t* current = data;
    ++tested;
    if ((int)code == current->result1 || (int)code == current->result2) {
        fprintf(stderr, "SUCCESS: %s\n", current->testid);
        ++passed;
    } else {
        fprintf(stderr, "ERROR: %s\n", current->testid);
    }
    spf_test_next(current);
}

static void spf_test_next(spf_test_t* current) {
    if (current == NULL) {
        current = testcases;
    } else {
        current = current + 1;
    }
    if (current->testid == NULL) {
        fprintf(stderr, "DONE: %d tests %d success (%d%%)\n", tested, passed, (passed * 100) / tested);
        exit(0);
    }
    const char* domain = strchr(current->sender, '@');
    if (domain != NULL) {
        ++domain;
    }
    spf_code_t res;
    if (spf_check(current->ip, domain, current->sender, current->helo, spf_test_done, false, current, &res) == NULL) {
        spf_test_done(res, NULL, current);
    }
}

int main(int argc, char *argv[])
{
    dns_use_local_conf("resolv.conf");
    log_level = LOG_NOTICE;
    spf_test_next(NULL);
    return server_loop(NULL, NULL, NULL, NULL, NULL);
}

/* vim:set et sw=4 sts=4 sws=4: */
