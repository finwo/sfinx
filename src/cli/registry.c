#include "registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cli_command *cli_commands = NULL;
char               *command_list = NULL;

// Command list {{{
//
// The rendered command table, refreshed on every registration
//   commands register from constructors, so the list is final before main runs
//   the format is what the global usage has always printed

static void command_list_render(void) {
  struct cli_command *command;
  char               *text;
  size_t              len = sizeof("commands:\n");
  size_t              at  = 0;

  for (command = cli_commands; command; command = command->next) {
    len += (size_t)snprintf(NULL, 0, "  %-12s %s\n", command->display, command->description);
  }
  text = malloc(len);
  if (!text) return;
  at += (size_t)snprintf(text + at, len - at, "commands:\n");
  for (command = cli_commands; command; command = command->next) {
    at += (size_t)snprintf(text + at, len - at, "  %-12s %s\n", command->display, command->description);
  }
  free(command_list);
  command_list = text;
}
// }}}

// Registry {{{
//
// Commands prepend themselves on load
//   names is a NULL terminated alias list, argv[0] is the command name

void cli_command_register(struct cli_command *command) {
  if (!command) return;
  command->next = cli_commands;
  cli_commands  = command;
  command_list_render();
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
// }}}
