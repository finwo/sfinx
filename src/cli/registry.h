#ifndef __SFINX_CLI_REGISTRY_H__
#define __SFINX_CLI_REGISTRY_H__

typedef int (*cli_main_fn)(int argc, char **argv);

void cli_register(const char *name, cli_main_fn fn);
cli_main_fn cli_find(const char *name);
char * cli_registered();

#endif // __SFINX_CLI_REGISTRY_H__
