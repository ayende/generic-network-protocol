#include <stdio.h>
#include <stdarg.h>
#include "network.h"


void* on_connection_created(struct connection* connection){
	return NULL;
}
void on_connection_dropped(struct connection* connection, void* state) {

}

int on_connection_recv(struct cmd* cmd, void* state) {
	int rc;
	if (strcmp("GET", cmd->argv[0]) == 0 && cmd->argc > 1) {
		rc = connection_reply_format(cmd, cmd->argv[1]);
	}
	else {
		rc = connection_reply_format(cmd, "Unknown command: %s", cmd->argv[0]);
	}
	return rc;
}

int main(int argc, char **argv)
{
	int rc;
	int sock = -1;
	struct server_state* srv_state;

	const char* cert = "example-com.cert.pem";
	const char* key = "example-com.key.pem";

	struct server_state_init options = { cert, key, INADDR_ANY, 4433 };
	srv_state = server_state_create(&options);

	if (srv_state == NULL) {
		goto handle_error;
	}
	struct connection_setup cb = {
		print_all_errors,
		on_connection_created,
		on_connection_dropped,
		on_connection_recv
	};
	server_state_register_connection_setup(srv_state, cb);

	if (!server_state_register_certificate_thumbprint(srv_state, "1776821DB1002B0E2A9B4EE3D5EE14133D367009")) {
		goto handle_error;
	}

	if (!server_state_register_certificate_thumbprint(srv_state, "AE535D83572189D3EDFD1568DC76275BE33B07F5")) {
		goto handle_error;
	}

	printf("Ready...\n");

	rc = server_state_run(srv_state); // app stops here

handle_error:

	if(srv_state != NULL)
		server_state_drop(srv_state);

	print_all_errors();
	

	return rc;
}
