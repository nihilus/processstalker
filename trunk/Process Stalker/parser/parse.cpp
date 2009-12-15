
/*  A Bison parser, made from string.y with Bison version GNU Bison version 1.24
  */

#define YYBISON 1  /* Identify Bison output.  */

#define	ERROR_TOKEN	258
#define	EQUAL	259
#define	CT_CHAR	260
#define	CT_INT	261
#define	CT_VOID	262
#define	CT_FMTCHAR	263
#define	CT_WCHAR	264
#define	CT_FMTWCHAR	265
#define	DIR_IN	266
#define	DIR_OUT	267
#define	DIR_BOTH	268
#define	CALL_CDECL	269
#define	CALL_FASTCALL	270
#define	CALL_STDCALL	271
#define	ID	272
#define	STRING	273
#define	HEXID	274
#define	MODID	275

#line 3 "string.y"


/* ------------------------------------------------------------------
   Initial code (copied verbatim to the output file)
   ------------------------------------------------------------------ */

// Includes
#include <malloc.h>  // _alloca is used by the parser
#include <string.h>  // strcpy

#include "lex.h"     // the lexer

// Some yacc (bison) defines
#define YYDEBUG 1	      // Generate debug code; needed for YYERROR_VERBOSE
#define YYERROR_VERBOSE // Give a more specific parse error message 

// Forward references
void yyerror (char *msg);



//
// This is used for the C-Style Flex/Yacc code -> C++ code transition 
//
#include <string>
#include <vector>
#include <stack>

using namespace std;

#include "tracedefs.hpp"

t_Tracevector			TraceDefinitions;

//
// END transition code
//

//
// Temporary Variables for use in the sub-expressions
// while parsing. This is ugly, but nobody said I'm a 
// coder.
//
t_Tracedef_Def				TT;

stack<t_Tracedef_Ctype>			TempArgs;
stack<t_Tracedef_Direction>		TempDirs;
stack<string>					TempNames;

t_Tracedef_Ctype			RetType;
string						RetMatch = "";
t_Tracedef_Ctype			TempType;
string						TempName  = "";
string						TempName2 = "";
string						TempMatch = "";
string						TempMod = "";
t_Tracedef_Direction		TempDir = unknown;
t_Tracedef_Callconv			TempCall = CV_CDECL;

void ClearTempArgs() {
	while (!TempArgs.empty()) TempArgs.pop();
	while (!TempDirs.empty()) TempDirs.pop();
	while (!TempNames.empty()) TempNames.pop();
}

void ReInitTemps() {
	RetMatch = "";
	TempMatch = "";
	TempName = "";
	TempMod = "";
	TempName2 = "";
	TempDir = unknown;
	TempCall = CV_CDECL;
}


#line 85 "string.y"
typedef union {
   char *str;
} YYSTYPE;

#ifndef YYLTYPE
typedef
  struct yyltype
    {
      int timestamp;
      int first_line;
      int first_column;
      int last_line;
      int last_column;
      char *text;
   }
  yyltype;

#define YYLTYPE yyltype
#endif

#include <stdio.h>

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		60
#define	YYFLAG		-32768
#define	YYNTBASE	29

#define YYTRANSLATE(x) ((unsigned)(x) <= 275 ? yytranslate[x] : 42)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    22,
    23,    27,     2,    24,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    28,    21,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    25,     2,    26,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     2,     3,     4,     5,
     6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
    16,    17,    18,    19,    20
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     2,     5,     6,     8,    14,    21,    24,    26,    30,
    32,    36,    37,    40,    42,    47,    52,    57,    59,    61,
    64,    66,    69,    71,    74,    77,    80,    83,    88,    91,
    93,    95,    97,    98,   100,   102,   104
};

static const short yyrhs[] = {    30,
     0,    30,    31,     0,     0,    21,     0,    33,    37,    22,
    23,    21,     0,    33,    37,    22,    32,    23,    21,     0,
     1,    21,     0,    34,     0,    32,    24,    34,     0,    36,
     0,    41,     4,    36,     0,     0,    35,    40,     0,    35,
     0,    25,    11,    26,    36,     0,    25,    12,    26,    36,
     0,    25,    13,    26,    36,     0,    36,     0,     5,     0,
     5,    27,     0,     6,     0,     6,    27,     0,     7,     0,
     7,    27,     0,     8,    27,     0,     9,    27,     0,    10,
    27,     0,    38,    39,    28,    40,     0,    38,    40,     0,
    14,     0,    15,     0,    16,     0,     0,    20,     0,    17,
     0,    19,     0,    18,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   117,   121,   122,   126,   127,   140,   166,   170,   174,   181,
   182,   183,   187,   188,   192,   193,   194,   195,   199,   200,
   201,   202,   203,   204,   205,   206,   207,   211,   212,   216,
   217,   218,   219,   223,   227,   228,   232
};

static const char * const yytname[] = {   "$","error","$undefined.","ERROR_TOKEN",
"EQUAL","CT_CHAR","CT_INT","CT_VOID","CT_FMTCHAR","CT_WCHAR","CT_FMTWCHAR","DIR_IN",
"DIR_OUT","DIR_BOTH","CALL_CDECL","CALL_FASTCALL","CALL_STDCALL","ID","STRING",
"HEXID","MODID","';'","'('","')'","','","'['","']'","'*'","':'","program","statement_list",
"statement","arguments_expression","return_expression","single_argument","directed_ctype",
"ctype_expression","name_expression","callconv","mod_identifier","identifier",
"string",""
};
#endif

static const short yyr1[] = {     0,
    29,    30,    30,    31,    31,    31,    31,    32,    32,    33,
    33,    33,    34,    34,    35,    35,    35,    35,    36,    36,
    36,    36,    36,    36,    36,    36,    36,    37,    37,    38,
    38,    38,    38,    39,    40,    40,    41
};

static const short yyr2[] = {     0,
     1,     2,     0,     1,     5,     6,     2,     1,     3,     1,
     3,     0,     2,     1,     4,     4,     4,     1,     1,     2,
     1,     2,     1,     2,     2,     2,     2,     4,     2,     1,
     1,     1,     0,     1,     1,     1,     1
};

static const short yydefact[] = {     3,
     0,     0,    19,    21,    23,     0,     0,     0,    37,     4,
     2,    33,    10,     0,     7,    20,    22,    24,    25,    26,
    27,    30,    31,    32,     0,     0,     0,     0,    35,    36,
    34,     0,    29,    11,     0,     0,     0,     8,    14,    18,
     0,     5,     0,     0,     0,     0,     0,    13,    28,     0,
     0,     0,     6,     9,    15,    16,    17,     0,     0,     0
};

static const short yydefgoto[] = {    58,
     1,    11,    37,    12,    38,    39,    40,    25,    26,    32,
    33,    14
};

static const short yypact[] = {-32768,
     1,    -8,    31,    32,    36,    37,    38,    39,-32768,-32768,
-32768,   -11,-32768,    56,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,-32768,    40,    35,    34,    22,-32768,-32768,
-32768,    41,-32768,-32768,    46,    12,    33,-32768,    -5,-32768,
    -5,-32768,    42,    44,    45,    51,    28,-32768,-32768,    34,
    34,    34,-32768,-32768,-32768,-32768,-32768,    61,    73,-32768
};

static const short yypgoto[] = {-32768,
-32768,-32768,-32768,-32768,    27,-32768,    -1,-32768,-32768,-32768,
     7,-32768
};


#define	YYLAST		74


static const short yytable[] = {    13,
    -1,     2,    22,    23,    24,     3,     4,     5,     6,     7,
     8,    29,    15,    30,   -12,   -12,   -12,   -12,     9,   -12,
   -12,    10,    43,    44,    45,    34,     3,     4,     5,     6,
     7,     8,     3,     4,     5,     6,     7,     8,     3,     4,
     5,     6,     7,     8,    35,    48,    36,    49,    55,    56,
    57,    29,    36,    30,    31,    46,    47,    16,    17,    27,
    59,    28,    18,    19,    20,    21,    42,    50,    41,    51,
    52,    53,    60,    54
};

static const short yycheck[] = {     1,
     0,     1,    14,    15,    16,     5,     6,     7,     8,     9,
    10,    17,    21,    19,    14,    15,    16,    17,    18,    19,
    20,    21,    11,    12,    13,    27,     5,     6,     7,     8,
     9,    10,     5,     6,     7,     8,     9,    10,     5,     6,
     7,     8,     9,    10,    23,    39,    25,    41,    50,    51,
    52,    17,    25,    19,    20,    23,    24,    27,    27,     4,
     0,    22,    27,    27,    27,    27,    21,    26,    28,    26,
    26,    21,     0,    47
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

#ifndef alloca
#ifdef __GNUC__
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi)
#include <alloca.h>
#else /* not sparc */
#if defined (MSDOS) && !defined (__TURBOC__)
#include <malloc.h>
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
#include <malloc.h>
 #pragma alloca
#else /* not MSDOS, __TURBOC__, or _AIX */
#ifdef __hpux
#ifdef __cplusplus
extern "C" {
void *alloca (unsigned int);
};
#else /* not __cplusplus */
void *alloca ();
#endif /* not __cplusplus */
#endif /* __hpux */
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc.  */
#endif /* not GNU C.  */
#endif /* alloca not defined.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	return(0)
#define YYABORT 	return(1)
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
int yyparse (void);
#endif

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(FROM,TO,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (from, to, count)
     char *from;
     char *to;
     int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *from, char *to, int count)
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 192 "bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#else
#define YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#endif

int
yyparse(YYPARSE_PARAM)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
      yyss = (short *) alloca (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss1, (char *)yyss, size * sizeof (*yyssp));
      yyvs = (YYSTYPE *) alloca (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs1, (char *)yyvs, size * sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) alloca (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls1, (char *)yyls, size * sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 4:
#line 126 "string.y"
{ /* ignore */ ;
    break;}
case 5:
#line 127 "string.y"
{

						TT.Args.clear();
						TT.Return = RetType;
						TT.ReturnMatch = RetMatch;
						TT.Name = TempName2;
						TT.Module = TempMod;
						TT.CallConv = TempCall;
						TraceDefinitions.push_back(TT);
						
						ReInitTemps();
						ClearTempArgs();
						;
    break;}
case 6:
#line 140 "string.y"
{
						t_Tracedef_Argument			ag;

						TT.Args.clear();
						TT.Return = RetType;
						TT.ReturnMatch = RetMatch;
						TT.Name = TempName2;
						TT.Module = TempMod;
						TT.CallConv = TempCall;
						
						while (!TempArgs.empty()) {
							ag.Type = TempArgs.top();
							ag.Dir = TempDirs.top();
							ag.Name = TempNames.top();
							TT.Args.insert( TT.Args.begin(), ag );
							TempArgs.pop();
							TempDirs.pop();
							TempNames.pop();
						}

						TraceDefinitions.push_back(TT);
						
						ReInitTemps();
						ClearTempArgs();

						;
    break;}
case 7:
#line 166 "string.y"
{/* ignore */;
    break;}
case 8:
#line 170 "string.y"
{	TempDirs.push(TempDir); 
															TempArgs.push(TempType);
															TempNames.push(TempName); 
														;
    break;}
case 9:
#line 174 "string.y"
{	TempDirs.push(TempDir); 
															TempArgs.push(TempType); 
															TempNames.push(TempName);
														;
    break;}
case 10:
#line 181 "string.y"
{ RetMatch = ""; TempMatch=""; RetType = TempType; ;
    break;}
case 11:
#line 182 "string.y"
{ RetMatch = TempMatch; TempMatch=""; RetType = TempType; ;
    break;}
case 12:
#line 183 "string.y"
{ RetType = tr_VOID; RetMatch = ""; TempMatch=""; ;
    break;}
case 14:
#line 188 "string.y"
{ TempName = ""; ;
    break;}
case 15:
#line 192 "string.y"
{ TempDir = in; ;
    break;}
case 16:
#line 193 "string.y"
{ TempDir = out; ;
    break;}
case 17:
#line 194 "string.y"
{ TempDir = both; ;
    break;}
case 18:
#line 195 "string.y"
{ TempDir = unknown; ;
    break;}
case 19:
#line 199 "string.y"
{ TempType = tr_CHAR; ;
    break;}
case 20:
#line 200 "string.y"
{ TempType = tr_PCHAR; ;
    break;}
case 21:
#line 201 "string.y"
{ TempType = tr_INT; ;
    break;}
case 22:
#line 202 "string.y"
{ TempType = tr_PINT; ;
    break;}
case 23:
#line 203 "string.y"
{ TempType = tr_VOID; ;
    break;}
case 24:
#line 204 "string.y"
{ TempType = tr_PVOID; ;
    break;}
case 25:
#line 205 "string.y"
{ TempType = tr_PFMTCHAR; ;
    break;}
case 26:
#line 206 "string.y"
{ TempType = tr_PWCHAR; ;
    break;}
case 27:
#line 207 "string.y"
{ TempType = tr_PFMTWCHAR; ;
    break;}
case 28:
#line 211 "string.y"
{ TempName2 = TempName; ;
    break;}
case 29:
#line 212 "string.y"
{ TempName2 = TempName; TempMod = ""; ;
    break;}
case 30:
#line 216 "string.y"
{ TempCall = CV_CDECL; ;
    break;}
case 31:
#line 217 "string.y"
{ TempCall = CV_FASTCALL; ;
    break;}
case 32:
#line 218 "string.y"
{ TempCall = CV_STDCALL; ;
    break;}
case 33:
#line 219 "string.y"
{ TempCall = CV_CDECL; ;
    break;}
case 34:
#line 223 "string.y"
{ TempMod = yyvsp[0].str; ;
    break;}
case 35:
#line 227 "string.y"
{ TempName = yyvsp[0].str; ;
    break;}
case 36:
#line 228 "string.y"
{ TempName = yyvsp[0].str; ;
    break;}
case 37:
#line 232 "string.y"
{ TempMatch = yyvsp[0].str; ;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 487 "bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;
}
#line 235 "string.y"

/* ------------------------------------------------------------------
   Additional code (again copied verbatim to the output file)
   ------------------------------------------------------------------ */

