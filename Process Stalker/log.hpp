#ifndef __LOG_HPP__
#define __LOG_HPP__

#include <stdio.h>
#include <stack>
#include <string>

using namespace std;

#define LOG_DEBUG		1
#define LOG_VERBOSE		2
#define LOG_INFO		3
#define LOG_NOTICE		3		// same as INFO, just convenience 
#define LOG_WARNING		4
#define LOG_ERROR		5
#define LOG_SHUTUP		6

class Logger {

public:
	string		Name;

	Logger(void);
	Logger(char *name);
	~Logger(void);

	//
	// Setting the log level
	//
	void set(unsigned int level);
	void push(unsigned int level);
	void pop(void);
	
	//
	// In case someone is interested
	//
	unsigned int getLevel(void) { return LogLevel; }

	//
	// Writing to log, format string vulnerability included
	//
	void append(unsigned int level, char *fmt, ...);
	void appendError(unsigned int level, char *fmt, ...);

protected:
	FILE					*log_handle;
	unsigned int			LogLevel;
	stack <unsigned int>	LevelStack;

	char *LevelName(unsigned int l);
};


extern Logger log;

#endif __LOG_HPP__