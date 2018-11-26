#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include "network.h"

int create_server_socket(int port)
{
	int s;
	int rc;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		push_error(ENETUNREACH, "Unable to create socket for listening on port: %i", port);
		return -1;
	}

	rc = bind(s, (struct sockaddr*)&addr, sizeof(addr));
	if (rc != 0) {
		closesocket(s);
		push_error(rc, "Unable to bind socket on port: %i, error: %i", port, rc);
		return -1;
	}

	rc = listen(s, 2);

	if ( rc != 0 ) {
		closesocket(s);
		push_error(rc, "Unable to listen to socket on port: %i, error: %i", port, rc);
		return -1;
	}

	return s;
}


int main(int argc, char **argv)
{
	int rc;
	int sock = -1;
	struct server_state* srv_state;

	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		perror("Unable to initialize WSA properly");
		return ENETDOWN;
	}

	const char* cert = "c:\\Work\\temp\\example-com.cert.pem";
	const char* key = "c:\\Work\\temp\\example-com.key.pem";

	srv_state = server_state_create(cert, key);

	if (srv_state == NULL) {
		goto handle_error;
	}

	sock = create_server_socket(4433);
	if (sock == -1) {
		goto handle_error;
	}

	/* Handle connections */
	while (1) {
		struct sockaddr_in addr;
		struct connection* con;
		unsigned int len = sizeof(addr);
		char buffer[256];

		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client == INVALID_SOCKET) {
			push_error(ENETRESET, "Unable to accept connection, error: %i", GetLastError());
			goto handle_error; // failure to accept impacts everything, we should close listening
		}

		con = connection_create(srv_state, client);

		if (con == NULL)
		{
			closesocket(client);
			print_all_errors();
			continue; // accept the next connection...
		}

		if (connection_write_format(con, "Hello World\n") == 0) {
			goto handle_connection_error;
		}

		while (1)
		{
			rc = connection_read(con, buffer, sizeof buffer);
			if (rc == 0) {
				goto handle_connection_error;
			}

			if (connection_write(con, buffer, rc) == 0) {
				goto handle_connection_error;
			}
		}

	handle_connection_error:
		print_all_errors();
		if (con != NULL) {
			connection_drop(con);
		}
		// now go back and accept another connection
	}

handle_error:

	if(srv_state != NULL)
		server_state_drop(srv_state);

	if (sock != -1)
		closesocket(sock);

	print_all_errors();
	

	return EINVAL;
}
