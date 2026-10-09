#ifndef __SFINX_CLI_REGISTRY_H__
#define __SFINX_CLI_REGISTRY_H__

// Registry {{{
//
// Commands prepend themselves on load
//   names is a NULL terminated alias list, argv[0] is the command name

struct cli_command {
  struct cli_command *next;
  const char *const  *names;
  const char         *display;
  const char         *description;
  const char         *help;
  int (*fn)(int argc, const char **argv);
};

extern struct cli_command *cli_commands;
extern char               *command_list;

void                cli_command_register(struct cli_command *command);
struct cli_command *cli_command_find(const char *name);
// }}}

#endif  // __SFINX_CLI_REGISTRY_H__
