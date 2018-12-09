#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "network.h"


tls_uv_connection_state_t*  create_connection(void){
	static int counter = 0;
	tls_uv_connection_state_t* connection = malloc(sizeof(tls_uv_connection_state_t));
	if (connection == NULL)
		return NULL;
	*(int*)(connection->user_data)= ++counter;

	printf("Connection created %d\n", *(int*)connection->user_data);

	return connection;
}

void on_connection_dropped(tls_uv_connection_state_t* connection) {
	print_all_errors();
	printf("Connection dropped %d\n", *(int*)connection->user_data);
}

int on_connection_recv(tls_uv_connection_state_t* connection, cmd_t* cmd) {
	int rc;
	if (strcasecmp("GET", cmd->argv[0]) == 0 && cmd->argc > 1) {
		rc = connection_reply_format(cmd, "%s", cmd->argv[1]);
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
	server_state_t* srv_state;

	const char* cert = "example-com.cert.pem";
	const char* key = "example-com.key.pem";

	connection_handler_t handler = {
		print_all_errors,
		on_connection_dropped,
		create_connection,
		on_connection_recv
	};

	server_state_init_t options = { 
		cert, 
		key, 
		"0.0.0.0", 
		4433,
		&handler,
		{ "1776821DB1002B0E2A9B4EE3D5EE14133D367009" , "AE535D83572189D3EDFD1568DC76275BE33B07F5" },
		2
	};
	srv_state = server_state_create(&options);

	if (srv_state == NULL) {
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
