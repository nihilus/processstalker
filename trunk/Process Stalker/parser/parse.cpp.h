typedef union {
   char *str;
} YYSTYPE;
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


extern YYSTYPE yylval;
