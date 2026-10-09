#include "registry.h"

#include <string.h>

struct cli_command *cli_commands = NULL;

void cli_command_register(struct cli_command *command) {
  if (!command) return;
  command->next = cli_commands;
  cli_commands  = command;
}

struct cli_command *cli_command_find(const char *name) {
  struct cli_command *command;
  if (!name) return NULL;
  for (command = cli_commands; command; command = command->next) {
    for (const char *const *alias = command->names; alias && *alias; alias++) {
      if (!strcmp(*alias, name)) {
        return command;
      }
    }
  }
  return NULL;
}
