#include <string>
#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <stack>

using namespace std;

#include "log.hpp"


Logger::Logger() {
	log_handle = stdout;
	LogLevel = LOG_WARNING;
	Name="";
}


Logger::Logger(char *name) {
	log_handle = stdout;
	LogLevel = LOG_WARNING;
	Name = name;
}


Logger::~Logger() {
}


void Logger::set(unsigned int level) {

	LogLevel=level;
}


void Logger::push(unsigned int level) {

	append(LogLevel,"Setting log level to %s\n",LevelName(level));
	LevelStack.push(LogLevel);
	LogLevel = level;
}


void Logger::pop(void) {
	unsigned int	l;

	if ( ! LevelStack.empty() ) {
		l = LevelStack.top();
		LevelStack.pop();
		append(LogLevel,"Reverting log level to %s\n",LevelName(l));
		LogLevel=l;
	}
}


void Logger::append(unsigned int level, char *fmt, ...) {
	va_list		ap;

	if (level >= LogLevel ) {

		if (Name.length() > 0) 
			fprintf(log_handle,"%s ",Name.c_str());

		fprintf(log_handle,"[%s] ",LevelName(level));
			
		va_start(ap,fmt);
		vfprintf(log_handle, fmt, ap);
		va_end(ap);
	}
}


void Logger::appendError(unsigned int level, char *fmt, ...) {
	va_list			ap;
	TCHAR			szBuf[80]; 
    LPTSTR			lpMsgBuf;
    DWORD			dw = GetLastError(); 
	unsigned int	i;

	if (level >= LogLevel ) {

		if (Name.length() > 0) 
			fprintf(log_handle,"%s ",Name.c_str());

		FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | 
			FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			dw,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPTSTR) &lpMsgBuf,
			0, NULL );

		for (i=0; i<strlen(lpMsgBuf); i++) {
			if ( (lpMsgBuf[i] == '\r') || (lpMsgBuf[i] == '\n') )
				lpMsgBuf[i]=' ';
		}
		
		wsprintf(szBuf, " (windows error %d: %s)\n", dw, lpMsgBuf); 
		
		fprintf(log_handle,"[%s] ",LevelName(level));
			
		va_start(ap,fmt);
		vfprintf(log_handle, fmt, ap);
		va_end(ap);

		fprintf(log_handle, szBuf);

		LocalFree(lpMsgBuf);
	}
}


char *Logger::LevelName(unsigned int level) {
	switch(level) {
	case LOG_DEBUG:		return "DEBUG";
	case LOG_VERBOSE:	return "VERBOSE";
	case LOG_INFO:		return "INFO";
	case LOG_WARNING:	return "WARNING";
	case LOG_ERROR:		return "ERROR"; 
	default:			return "FUCKED UP";
	}
}