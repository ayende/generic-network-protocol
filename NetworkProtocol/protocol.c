#include "internal.h"


int connection_reply(struct cmd* c, void* buf, size_t len) {
	char* msg;
	int rc;
	if (c->sequence == NULL) {
		push_error(EINVAL, "Cannot reply to a message that has no Sequence header: %s", c->argv[0]);
		return 0;
	}

	rc = asprintf(&msg, "OK\r\nSequence: %s\r\nSize: %i\r\n\r\n", c->sequence, len);
	if (rc == -1) {
		push_error(EINVAL, "Failed to format message headers to write to connection");
		return 0;
	}
	// here we assume that this is a tiny write that will be buffered
	// and not be sent on its own packet
	rc = connection_write(c->connection, msg, rc);

	free(msg);

	if (rc == 0)
		return rc;

	rc = connection_write(c->connection, buf, len);

	return rc;
}

int connection_reply_format(struct cmd* c, const char* format, ...) {
	va_list ap;
	int rc;
	va_start(ap, format);
	char * msg;
	int len = vasprintf(&msg, format, ap);
	va_end(ap);

	if (len == -1) {
		push_error(EINVAL, "Failed to format message to write to connection");
		return 0;
	}

	rc = connection_reply(c, msg, len);
	free(msg);
	return rc;
}


static cmd_t* parse_command(tls_uv_connection_state_t* c, char* buffer, size_t len) {
	char* line_ctx = NULL, *ws_ctx = NULL, *line, *arg;
	struct cmd* cmd = NULL;
	char* copy = malloc(len+1);
	if (copy == NULL) {
		push_error(ENOMEM, "Unable to allocate command memroy");
		goto error_cleanup;
	}
	// now we need to have our own private copy of this
	memcpy(copy, buffer, len);
	copy[len] = 0; // ensure null terminator!

	cmd = calloc(1, sizeof(struct cmd));
	if (cmd == NULL) {
		push_error(ENOMEM, "Unable to allocate command memroy");
		goto error_cleanup;
	}
	cmd->connection = c;
	cmd->cmd_buffer = copy;
	line = strtok_s(copy, "\r\n", &line_ctx);
	if (line == NULL) {
		push_error(EINVAL, "Unable to find \r\n in the provided buffer");
		goto error_cleanup;
	}
	arg = strtok_s(line, " ", &ws_ctx);
	if (arg == NULL) {
		push_error(EINVAL, "Invalid message command line: %s", line);
		goto error_cleanup;
	}

	do
	{
		cmd->argc++;
		cmd->argv = realloc(cmd->argv, sizeof(char*) * cmd->argc);
		cmd->argv[cmd->argc - 1] = arg;
		arg = strtok_s(NULL, " ", &ws_ctx);
	} while (arg != NULL);

	while (1)
	{
		line = strtok_s(NULL, "\r\n", &line_ctx);
		if (line == NULL)
			break;
		arg = strtok_s(line, ":", &ws_ctx);

		if (arg == NULL) {
			push_error(EINVAL, "Header line does not contain ':' separator: %s", line);
			goto error_cleanup;
		}

		while (*ws_ctx != 0 && *ws_ctx == ' ')
			ws_ctx++; // skip initial space

		cmd->headers_count++;
		cmd->headers = realloc(cmd->headers, sizeof(struct header) *cmd->headers_count);
		cmd->headers[cmd->headers_count - 1].key = arg;
		cmd->headers[cmd->headers_count - 1].value = ws_ctx;

		if (strcasecmp("Sequence", arg) == 0) {
			cmd->sequence = ws_ctx;
		}
	}
	return cmd;

error_cleanup:
	if (copy != NULL)
		free(copy);
	if (cmd != NULL) {
		cmd_drop(cmd);
	}
	return NULL;
}

void cmd_drop(struct cmd * cmd)
{
	if (cmd->argv != NULL)
		free(cmd->argv);
	if (cmd->headers != NULL)
		free(cmd->headers);
	if (cmd->cmd_buffer != NULL)
		free(cmd->cmd_buffer);
	free(cmd);
}


int read_message(tls_uv_connection_state_t* c, void* buffer, int nread) {
	while (nread > 0)
	{
		int to_copy = MSG_SIZE - c->used_buffer;
		to_copy = to_copy < nread ? to_copy : nread;
		nread -= to_copy;
		memcpy(c->buffer, buffer, to_copy);
		c->used_buffer += to_copy;
		
		// first, need to check if we already
		// read the value from the network
		if (c->used_buffer > 0) {
			char* final = strnstr(c->buffer + c->to_scan, "\r\n\r\n", c->used_buffer - c->to_scan);
			if (final != NULL) {
				cmd_t* cmd = parse_command(c, c->buffer, final - c->buffer + 2/*include one \r\n*/);

				int rc = c->server->options.handler->connection_recv(c, cmd);

				// explicitly not freeing it, this should be done by the caller
				// cmd_drop(cmd);

				if (rc == 0)
					return 0;

				// now move the rest of the buffer that doesn't belong to this command 
				// adding 4 for the length of the msg separator (\r\n\r\n)
				c->used_buffer -= (final + 4) - c->buffer;
				memmove(c->buffer, final + 4, c->used_buffer);
				c->to_scan = 0;
				continue;
			}
			c->to_scan = c->used_buffer - 3 < 0 ? 0 : c->used_buffer - 3;
		}
		if (MSG_SIZE - c->used_buffer == 0) {
			push_error(EINVAL, "Message size is too large, after 8KB, "
				"couldn't find \r\n separator, aborting connection.");
			return 0;
		}
	}
	return 1;
}
