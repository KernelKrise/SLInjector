#ifndef HOOKING_H
#define HOOKING_H

#define JMP_HOOK_SIZE 17

int hook_function(const char *target_function, void *hook, unsigned char *saved_function_instructions);
int unhook_function(const char *target_function, unsigned char *saved_function_instructions);

#endif // HOOKING_H
