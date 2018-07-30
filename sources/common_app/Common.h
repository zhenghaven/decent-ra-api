#pragma once

#include <cstdio>
#include <cassert>

template<typename Base, typename T>
inline bool instanceof(const T *ptr) 
{
	return dynamic_cast<const Base*>(ptr) != nullptr;
}

enum class ConsoleColors 
{
	Red		= 0,
	Green	= 1,
	Yellow	= 2,
	Blue	= 3,
	Magenta	= 4,
	Cyan	= 5,
	White	= 6,
	Black	= 7,
	Default	= 8,
};

void SetConsoleColor(ConsoleColors foreground, ConsoleColors background);

#ifndef RELEASE_VER

#define LOGI(...)   printf(" I: "); \
					(void)printf(__VA_ARGS__); \
					printf("\n");
#define LOGW(...)   SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default); \
					printf("File:%s\nline:%d\n", __FILE__, __LINE__); \
					printf(" W: ");(void)printf(__VA_ARGS__); \
					printf("\n"); \
					SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
#define LOGE(...)   SetConsoleColor(ConsoleColors::Red, ConsoleColors::Black); \
					printf("File:%s\nline:%d\n", __FILE__, __LINE__); \
					printf(" E: "); \
					(void)printf(__VA_ARGS__); \
					printf("\n"); \
					assert(false); \
					SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
#define LOGP(...)   (void)printf(__VA_ARGS__);printf("\n");
#define ASSERT(Condition, ...) if(!(Condition)){LOGE(__VA_ARGS__);}
#define ASSERTP(Condition, ...)  if(!(Condition)){LOGE(__VA_ARGS__);}

#else

#define LOGI(...) 
#define LOGW(...) 
#define LOGE(...) 
#define LOGP(...)   (void)printf(__VA_ARGS__);printf("\n");
#define ASSERT(Condition, ...) 
#define ASSERTP(Condition, ...)  if(!(Condition)){LOGE(__VA_ARGS__);}

#endif // !RELEASE_VER
