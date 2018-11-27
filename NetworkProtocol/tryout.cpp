#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include "network.h"


void* on_connection_created(struct connection* connection){
	return NULL;
}
void on_connection_dropped(struct connection* connection, void* state) {

}

int on_connection_recv(struct connection* connection, void* state, void* buffer, size_t len) {
	return connection_write(connection, buffer, len);
}

int main(int argc, char **argv)
{
	int rc;
	int sock = -1;
	struct server_state* srv_state;

	const char* cert = "c:\\Work\\temp\\example-com.cert.pem";
	const char* key = "c:\\Work\\temp\\example-com.key.pem";

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

	rc = server_state_run(srv_state); // app stops here

	if (rc != 0) {
		goto handle_error;
	}


handle_error:

	if(srv_state != NULL)
		server_state_drop(srv_state);

	print_all_errors();
	

	return EINVAL;
}
